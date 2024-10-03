/*
 * Copyright (C) 2024 trustbroker.swiss team BIT
 *
 * This program is free software.
 * You can redistribute it and/or modify it under the terms of the GNU Affero General Public License
 * as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * See the GNU Affero General Public License for more details.
 * You should have received a copy of the GNU Affero General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 */

package swiss.trustbroker.oidc;

import java.io.IOException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import swiss.trustbroker.common.exception.ErrorCode;
import swiss.trustbroker.common.tracing.TraceSupport;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.oidc.session.OidcSessionSupport;
import swiss.trustbroker.util.ApiSupport;

@Slf4j
public class CustomFailureHandler implements AuthenticationFailureHandler {

	private final String type;

	private final RelyingPartyDefinitions relyingPartyDefinitions;

	private final TrustBrokerProperties trustBrokerProperties;

	private final HttpMessageConverter<OAuth2Error> errorResponseConverter;

	private final ApiSupport apiSupport;

	public CustomFailureHandler(String type,
			RelyingPartyDefinitions relyingPartyDefinitions,
			TrustBrokerProperties trustBrokerProperties) {
		this.type = type;
		this.relyingPartyDefinitions = relyingPartyDefinitions;
		this.trustBrokerProperties = trustBrokerProperties;
		this.apiSupport = new ApiSupport(trustBrokerProperties);
		this.errorResponseConverter = new OAuth2ErrorHttpMessageConverter();
	}

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException {
		var clientId = OidcSessionSupport.getOidcClientId(request);
		var client = relyingPartyDefinitions.getRelyingPartyByOidcClientId(clientId, null, trustBrokerProperties, true);
		var referrer = WebUtil.getHeader(HttpHeaders.REFERER, request);

		// exception from sub-systems
		String errMsg;
		if (exception instanceof OAuth2AuthenticationException authException) {
			// OIDC sub-system https://openid.net/specs/openid-connect-core-1_0.html#AuthError
			var error = authException.getError();
			errMsg = String.format("Failed OIDC %s for oidcClient=%s of rpIssuerId=%s and httpReferer=%s"
							+ " with errorCode=%s exceptionMessage='%s' exceptionClass=%s description='%s'",
					type, clientId, client != null ? client.getId() : null, referrer, error.getErrorCode(),
					exception.getMessage(), exception.getClass().getSimpleName(),
					getDescription(exception, error.getDescription()));
		}
		else if (exception instanceof Saml2AuthenticationException authException) {
			// federation handling using SAML
			var error = authException.getSaml2Error();
			errMsg = String.format("Failed SAML %s for oidcClient=%s of rpIssuerId=%s and httpReferer=%s"
							+ " with errorCode=%s exceptionMessage='%s' exceptionClass=%s description='%s'",
					type, clientId, client != null ? client.getId() : null, referrer, error.getErrorCode(),
					exception.getMessage(), exception.getClass().getSimpleName(),
					getDescription(exception, error.getDescription()));
		}
		else {
			// anything else
			errMsg = String.format("Failed %s for oidcClient=%s of rpIssuerId=%s httpReferer=%s"
							+ " with exceptionMessage='%s' exceptionClass=%s",
					type, clientId, client != null ? client.getId() : null, referrer,
					exception.getMessage(), exception.getClass().getName());
		}

		// construct redirect to OIDC client or service with service context
		var traceId = TraceSupport.getOwnTraceParent();
		var errorPage = apiSupport.getErrorPageUrl(ErrorCode.REQUEST_DENIED.getLabel(), traceId);
		var location = OidcExceptionHelper.buildLocationForAuthenticationException(request, exception, errorPage,
				trustBrokerProperties.getOidc().getIssuer(), "spring-security");

		// invalidate web session to not base authorization_code flow after refresh_token failures
		OidcSessionSupport.invalidateSession(request, response, trustBrokerProperties, clientId, errMsg);

		// choose failure notification approach
		var acceptHeader = request.getHeader(HttpHeaders.ACCEPT);
		if (acceptHeader != null && acceptHeader.contains(MediaType.APPLICATION_JSON_VALUE)) {
			handleFailureAsJsonError(errMsg, response, exception);
		}
		else if (location != null) {
			handleFailureWithClientRedirect(location, errMsg, acceptHeader, response);
		}
		else {
			handleFailureWithServiceRedirect(errorPage, errMsg, acceptHeader, request, response, exception);
		}
	}

	private void handleFailureWithClientRedirect(
			String location, String errMsg, String acceptHeader,
			HttpServletResponse response)
			throws IOException {
		log.error("OIDC client failure redirecting to redirectUri=\"{}\" accept='{}' caused by: {}",
				location, acceptHeader, errMsg);
		response.sendRedirect(location);
	}

	private void handleFailureWithServiceRedirect(
			String errorPage, String errMsg, String acceptHeader,
			HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
			throws IOException {
		log.error("OIDC client failure redirecting to errorPage=\"{}\" accept='{}' caused by: {}",
				errorPage, acceptHeader, errMsg);
		// store for later handling in OidcTxResponseWrapper / AppErrorViewResolver
		OidcExceptionHelper.saveAuthenticationException(request, exception);
		response.sendRedirect(errorPage);
	}

	private void handleFailureAsJsonError(
			String errMsg,
			HttpServletResponse response, AuthenticationException exception)
			throws IOException {
		log.error("OIDC client failure caused by: {}", errMsg);
		try (var httpResponse = new ServletServerHttpResponse(response)) {
			httpResponse.setStatusCode(HttpStatus.BAD_REQUEST);
			if (exception instanceof OAuth2AuthenticationException ex) {
				httpResponse.setStatusCode(mapOAuth2AuthenticationExceptionToHttpStatusCode(ex.getError()));
				errorResponseConverter.write(ex.getError(), null, httpResponse);
			}
		}
	}

	private static HttpStatusCode mapOAuth2AuthenticationExceptionToHttpStatusCode(OAuth2Error error) {
		if (OAuth2ErrorCodes.UNAUTHORIZED_CLIENT.equals(error.getErrorCode())) {
			return HttpStatus.UNAUTHORIZED;
		}
		if (OAuth2ErrorCodes.INVALID_CLIENT.equals(error.getErrorCode())) {
			return HttpStatus.UNAUTHORIZED;
		}
		if (OAuth2ErrorCodes.INVALID_TOKEN.equals(error.getErrorCode())) {
			return HttpStatus.UNAUTHORIZED;
		}
		if (OAuth2ErrorCodes.INSUFFICIENT_SCOPE.equals(error.getErrorCode())) {
			return HttpStatus.FORBIDDEN;
		}
		return HttpStatus.BAD_REQUEST;
	}

	// de-duplicate exception message and error description
	private static String getDescription(AuthenticationException exception, String errorDescription) {
		return errorDescription != null && !errorDescription.equals(exception.getMessage()) ? errorDescription : "";
	}

}
