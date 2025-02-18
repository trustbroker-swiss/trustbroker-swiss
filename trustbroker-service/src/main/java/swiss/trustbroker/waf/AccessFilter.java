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

package swiss.trustbroker.waf;

import java.io.IOException;
import java.util.regex.Pattern;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.WebSupport;

/**
 * Filter that responds with a 404 for URLs that we do not want to expose the Angular UI
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 2)
@Slf4j
@AllArgsConstructor
public class AccessFilter implements Filter {

	// all request paths that are allowed by this filter
	private static final String ALL_ALLOWED_PATH_REGEX = "^("
			// SPA - see app-routing-module and AppController code
			+ "/app|/app/.*"
			// APIs (/adfs/ls included below)
			+ "|/api/v1/.*"
			// SAML endpoints
			+ "|/adfs/.*|/HRD|/HRD/.*|/AdfsGui/.*|/FederationMetadata/.*|/federationmetadata/.*"
			// assets referenced by UI (some of which are unfortunately in the context root)
			+ "|/assets/.*|/js/.*|/[^/]*.(js|css|woff2?|ttf|eot|svg|html)"
			+ "|/favicon.ico"
			+ "|/robots.txt"
			// oidc services (spring-authorization-server and Keycloak fake)
			+ "|/oauth2/.*|/login/.*|/login|/logout|/logout/.*|/realms/.*|/saml2/.*|/userinfo|/.well-known/openid-configuration"
			// DEV only legacy API
			+ "|/trustbroker/adfs/ls"
			+ ")$";

	private static final String INTERNAL_ALLOWED_PATH_REGEX = "^("
			+ "/actuator/health|/actuator/info"
			+ "|" + ApiSupport.RECONFIG_URL
			+ "|" + ApiSupport.CONFIG_STATUS_API
			+ "|" + ApiSupport.CONFIG_SCHEMAS_API + "/.*"
			+ ")$";

	private static final Pattern ALL_ALLOWED_PATHS = Pattern.compile(ALL_ALLOWED_PATH_REGEX);

	private static final Pattern INTERNAL_ALLOWED_PATHS = Pattern.compile(INTERNAL_ALLOWED_PATH_REGEX);

	private final TrustBrokerProperties trustBrokerProperties;

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		var httpRequest = (HttpServletRequest) request;
		var httpResponse = (HttpServletResponse) response;
		var path = httpRequest.getRequestURI();

		// firewall
		if (INTERNAL_ALLOWED_PATHS.matcher(path).matches()) {
			if (WebSupport.isClientOnInternet(httpRequest, trustBrokerProperties.getNetwork())) {
				blockAndLogRequest(httpRequest, httpResponse);
			}
			else {
				chain.doFilter(request, response);
			}
		}
		else if (ALL_ALLOWED_PATHS.matcher(path).matches()) {
			chain.doFilter(request, response);
		}
		else {
			blockAndLogRequest(httpRequest, httpResponse);
		}
	}

	private void blockAndLogRequest(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws IOException {
		// favicon.ico by browser to be handled silently, shall come from assets (see test)
		var path = httpRequest.getRequestURI();
		if (log.isDebugEnabled()) {
			log.debug("Sending HTTP/404 NOT FOUND for path='{}' clientNetwork={} allowedAll='{}' allowedInternal='{}'",
					path, WebSupport.getClientNetwork(httpRequest, trustBrokerProperties.getNetwork()),
					ALL_ALLOWED_PATH_REGEX, INTERNAL_ALLOWED_PATH_REGEX);
		}
		httpResponse.sendError(HttpServletResponse.SC_NOT_FOUND);
	}

}
