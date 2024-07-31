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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.startsWith;
import static org.mockito.Mockito.doReturn;

import java.io.IOException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.savedrequest.SavedRequest;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.OidcProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.util.WebSupport;

class CustomFailureHandlerTest {

	static class CustomAuthenticationException extends AuthenticationException {

		CustomAuthenticationException(String message) {
			super(message);
		}

	}

	private static final String ERROR_URL = "/app/failure";

	private static final String RETURN_URL = "https://localhost/return";

	private static final String ISSUER = "https://localhost:4200";

	@Mock
	private RelyingPartyDefinitions relyingPartyDefinitions;

	@Mock
	private TrustBrokerProperties trustBrokerProperties;

	@Mock
	private SavedRequest savedRequest;

	private CustomFailureHandler customFailureHandler;

	@BeforeEach
	void setUp() {
		MockitoAnnotations.openMocks(this);
		customFailureHandler = new CustomFailureHandler("test", relyingPartyDefinitions, trustBrokerProperties);
	}

	@ParameterizedTest
	@MethodSource
	void testOnAuthenticationFailure(AuthenticationException exception, String redirectUri, String expectedRedirect)
			throws IOException {
		var rp = RelyingParty.builder().id("rpId").build();
		var clientId = "client1";
		var request = new MockHttpServletRequest();
		WebSupport.setTraceContext(request);
		request.setParameter(OidcUtil.OIDC_CLIENT_ID, clientId);
		request.addHeader(HttpHeaders.REFERER, "https://localhost");
		if (redirectUri != null) {
			var session = new MockHttpSession();
			request.setSession(session);
			doReturn(new String[] { redirectUri }).when(savedRequest).getParameterValues(OidcUtil.REDIRECT_URI);
			session.setAttribute(OidcExceptionHelper.SAVED_REQUEST, savedRequest);
		}
		var response = new MockHttpServletResponse();

		var oidcProperties = new OidcProperties();
		oidcProperties.setIssuer(ISSUER);
		doReturn(oidcProperties).when(trustBrokerProperties).getOidc();
		doReturn(rp).when(relyingPartyDefinitions).getRelyingPartyByOidcClientId(clientId, null, trustBrokerProperties, true);

		customFailureHandler.onAuthenticationFailure(request, response, exception);

		assertThat(response.getRedirectedUrl(), startsWith(expectedRedirect));
		if (redirectUri == null) {
			assertThat(request.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION), is(exception));
		}
	}

	static Object[][] testOnAuthenticationFailure() {
		return new Object[][] {
				{
					new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "ignored",
						"http://ignored"), OidcExceptionHelper.OAUTH_2_0_PARAMETER + "code"),
						RETURN_URL,
						RETURN_URL + "?error=invalid_request&error_description=code&error_uri=" +
								WebUtil.urlEncodeValue(ISSUER + ERROR_URL)
				},
				{
						new Saml2AuthenticationException(new Saml2Error(OAuth2ErrorCodes.INVALID_REQUEST,
								OidcExceptionHelper.CLIENT_AUTH_FAILED + "code"),
								"ignored"),
						RETURN_URL,
						RETURN_URL + "?error=invalid_request&error_description=code&error_uri=" +
								WebUtil.urlEncodeValue(ISSUER + ERROR_URL)
				},
				{
						new Saml2AuthenticationException(new Saml2Error(OAuth2ErrorCodes.INVALID_REQUEST,
								OidcExceptionHelper.CLIENT_AUTH_FAILED + "code"),
								"ignored"),
						null,
						ERROR_URL
				},
				{
						new CustomAuthenticationException("ignored"),
						RETURN_URL,
						ERROR_URL // cannot extract error code from custom exception
				}
		};
	}

}
