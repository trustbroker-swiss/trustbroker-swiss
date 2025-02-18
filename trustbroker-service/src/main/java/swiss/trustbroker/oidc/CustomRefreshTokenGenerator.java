/*
 * Derivative work of original class from org.springframework.security:spring-security-oauth2-authorization-server:1.2.x:
 * org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.CustomRefreshTokenGenerator
 *
 * https://spring.io/projects/spring-authorization-server
 *
 * License of original class:
 *
 * @license
 *
 * Copyright 2020-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package swiss.trustbroker.oidc;

import java.time.Instant;
import java.util.Collections;
import java.util.UUID;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import swiss.trustbroker.common.util.OidcUtil;

@AllArgsConstructor
@Slf4j
public final class CustomRefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2RefreshToken> {

	private final JwtEncoder jwtEncoder;

	private final JWKSource<SecurityContext> jwkSource;

	@Override
	public OAuth2RefreshToken generate(OAuth2TokenContext context) {
		if (context == null || !OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
			return null;
		}

		// track via session that was established during the federation
		var sessionId = JwtTokenCustomizer.getSidClaim(context.getPrincipal());

		// send back nonce to clients providing it
		var nonce = JwtTokenCustomizer.getNonce(context.getAuthorization());

		// validity range depending on client settings
		var issuedAt = Instant.now();
		var expiresAt = computeRefreshTokenExpiration(context, issuedAt);

		// build
		var jwsHeader = buildHeader();
		var claims = buildClaims(context, issuedAt, expiresAt, sessionId, nonce);
		var jwt = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));
		var refreshToken = new OAuth2RefreshToken(jwt.getTokenValue(), issuedAt, expiresAt);
		log.debug("Created JWT refresh token iat={}, exp={}", issuedAt, expiresAt);
		return refreshToken;
	}

	private JwsHeader buildHeader() {
		var jwsAlgorithm = SignatureAlgorithm.RS256;
		var jwsHeaderBuilder = JwsHeader.with(jwsAlgorithm);
		var kid = JwkUtil.getKeyIdFromJwkSource(jwkSource);
		if (kid != null) {
			jwsHeaderBuilder.keyId(kid);
		}
		return jwsHeaderBuilder.build();
	}

	private static JwtClaimsSet buildClaims(OAuth2TokenContext context,
			Instant issuedAt, Instant expiresAt, String sessionId, String nonce) {
		var claimsBuilder = JwtClaimsSet.builder();
		String issuer = null;
		if (context.getAuthorizationServerContext() != null) {
			issuer = context.getAuthorizationServerContext()
							.getIssuer();
		}
		if (StringUtils.hasLength(issuer)) {
			claimsBuilder.issuer(issuer);
		}
		var registeredClient = context.getRegisteredClient();
		claimsBuilder.subject(context.getPrincipal()
									 .getName())
					 .id(UUID.randomUUID()
							 .toString())
					 .claim(OidcUtil.OIDC_TOKEN_TYPE, "Refresh")
					 .audience(Collections.singletonList(registeredClient.getClientId()))
					 .claim(OidcUtil.OIDC_AUTHORIZED_PARTY, registeredClient.getClientId())
					 .notBefore(issuedAt)
					 .issuedAt(issuedAt)
					 .expiresAt(expiresAt);
		if (!CollectionUtils.isEmpty(context.getAuthorizedScopes())) {
			claimsBuilder.claim(OidcUtil.OIDC_SCOPE, context.getAuthorizedScopes());
		}
		if (StringUtils.hasLength(nonce)) {
			claimsBuilder.claim(OidcParameterNames.NONCE, nonce);
		}
		if (StringUtils.hasLength(sessionId)) {
			claimsBuilder.claim(OidcUtil.OIDC_SESSION_ID, sessionId);
			claimsBuilder.claim(OidcUtil.OIDC_SESSION_STATE, sessionId);
		}
		return claimsBuilder.build();
	}

	private Instant computeRefreshTokenExpiration(OAuth2TokenContext context, Instant issuedAt) {
		var expiresAt = issuedAt;
		var source = "now";
		var client = context.getRegisteredClient();
		var authorization = context.getAuthorization();
		if (authorization != null) {
			var currentRefreshToken = authorization.getRefreshToken();
			if (currentRefreshToken != null && currentRefreshToken.getToken() != null) {
				source = "current";
				expiresAt = currentRefreshToken.getToken()
											   .getExpiresAt();
			}
			else {
				source = "settings";
				expiresAt = issuedAt.plus(client.getTokenSettings()
												.getRefreshTokenTimeToLive());
			}
		}
		log.debug("Expiration of refresh_token for clientId={} issuedAt={} expiresAt={} from source={}",
				client.getClientId(), issuedAt, expiresAt, source);
		if (issuedAt.isAfter(expiresAt)) {
			expiresAt = issuedAt;
		}
		return expiresAt;
	}

}
