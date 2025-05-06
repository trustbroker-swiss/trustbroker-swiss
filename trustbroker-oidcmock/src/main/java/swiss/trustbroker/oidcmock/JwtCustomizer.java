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

package swiss.trustbroker.oidcmock;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.firewall.RequestRejectedException;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@AllArgsConstructor
@Slf4j
public class JwtCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

	private final JWKSource<SecurityContext> jwkSource;

	private final OidcUserInfoService userInfoService;

	private final List<String> oidcParams = List.of("code", "state", "client_secret", "client_id", "grant_type", "redirect_uri");

	@Override
	public void customize(JwtEncodingContext context) {
		if (context == null) {
			return;
		}

		Map<String, String> customClaims = extractCustomClaimsFromReqParams();

		var authorization = context.getAuthorization();
		if (authorization == null) {
			throw new RequestRejectedException("Missing authorization, cannot set Token claims");
		}

		if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
			OidcUserInfo userInfo = userInfoService.loadUser(
					context.getPrincipal().getName());
			for (Map.Entry<String, String> entry : customClaims.entrySet()) {
				context.getClaims().claim(entry.getKey(), entry.getValue());
			}

			context.getClaims().claims(claims -> claims.putAll(userInfo.getClaims()));
		}

	}

	private Map<String, String> extractCustomClaimsFromReqParams() {
		Map<String, String> customClaims = new HashMap<>();

		RequestAttributes request = RequestContextHolder.getRequestAttributes();
		HttpServletRequest httpServletRequest = null;
		if (request instanceof ServletRequestAttributes sra) {
			httpServletRequest = sra.getRequest();
		}

		if (httpServletRequest == null) {
			return customClaims;
		}

		Map<String, String[]> parameterMap = httpServletRequest.getParameterMap();

		for(Map.Entry<String, String[]> entry : parameterMap.entrySet()){
			if (!oidcParams.contains(entry.getKey())) {
				customClaims.put(entry.getKey(), entry.getValue()[0]);
			}
		}
		return customClaims;
	}
}
