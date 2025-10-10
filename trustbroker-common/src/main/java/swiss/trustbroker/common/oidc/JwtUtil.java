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

package swiss.trustbroker.common.oidc;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.security.credential.Credential;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.common.util.StringUtil;

@Slf4j
public class JwtUtil {

	private static final int OPAQUE_TOKEN_PARTS = 1;

	public static final int JWT_TOKEN_PARTS  = 3;

	public static final int JWE_TOKEN_PARTS = 5;

	public static final String APPLICATION_JWT_TYPE = "application/jwt";

	public static JWTClaimsSet convertJoseClaimsToSpring(JwtClaimsSet claims) {
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();

		Object issuer = claims.getClaim("iss");
		if (issuer != null) {
			builder.issuer(issuer.toString());
		}

		String subject = claims.getSubject();
		if (StringUtils.hasText(subject)) {
			builder.subject(subject);
		}

		List<String> audience = claims.getAudience();
		if (!CollectionUtils.isEmpty(audience)) {
			builder.audience(audience);
		}

		String jwtId = claims.getId();
		if (StringUtils.hasText(jwtId)) {
			builder.jwtID(jwtId);
		}

		var expiresAt = claims.getExpiresAt();
		if (expiresAt != null) {
			builder.expirationTime(Date.from(expiresAt));
		}

		Instant notBefore = claims.getNotBefore();
		if (notBefore != null) {
			builder.notBeforeTime(Date.from(notBefore));
		}

		Instant issuedAt = claims.getIssuedAt();
		if (issuedAt != null) {
			builder.issueTime(Date.from(issuedAt));
		}

		Map<String, Object> customClaims = new HashMap<>();
		claims.getClaims().forEach((name, value) -> {
			if (!JWTClaimsSet.getRegisteredNames().contains(name)) {
				customClaims.put(name, value);
			}

		});
		if (!customClaims.isEmpty()) {
			Objects.requireNonNull(builder);
			customClaims.forEach(builder::claim);
		}

		return builder.build();
	}

	public static Payload signJwt(JwsHeader jwsHeader, JWTClaimsSet jwtClaimsSet, JWK jwk) {
		if (jwsHeader == null) {
			throw new TechnicalException("JWS header cannot be null for signing JWT");
		}
		var signingKid = jwsHeader.getKeyId();
		var signingAlgorithm = jwsHeader.getAlgorithm().toString();
		var signedJWT = new SignedJWT(
				new JWSHeader.Builder(JWSAlgorithm.parse(signingAlgorithm)).keyID(signingKid).build(), jwtClaimsSet);

		try {
			signedJWT.sign(new RSASSASigner(jwk.toRSAKey()));
			return new Payload(signedJWT);
		} catch (JOSEException e) {
			throw new TechnicalException("Could not sign JWT", e);
		}
	}

	public static String encryptJwt(JWEHeader jweHeader, Payload payload, JWK jwk) throws JOSEException {
		JWEObject jweObject = new JWEObject(jweHeader, payload);
		jweObject.encrypt(new RSAEncrypter(jwk.toRSAKey().toRSAPublicKey()));
		var keyID = jwk.getKeyID();
		log.debug("Payload={} encrypted with key={}", payload, keyID);
		return jweObject.serialize();
	}

	public static JWT parseJWT(String token) {
		try {
			return JWTParser.parse(token);
		} catch (Exception e) {
			return null;
		}
	}

	public static Jwt generateEncryptedToken(JwtEncoderParameters parameters, boolean signToken,
											 JWKSource<SecurityContext> jwkSource, Credential encryptionCredential,
											 JWEHeader jweHeader, String id) {
		JwsHeader jwsHeader = parameters.getJwsHeader();
		try {
			JwtClaimsSet claims = parameters.getClaims();
			var jwtClaimsSet = JwtUtil.convertJoseClaimsToSpring(claims);

			// sign
			Payload payload = OidcUtil.getAndSignPayload(jwtClaimsSet, signToken, jwsHeader, jwkSource, id);

			// encrypt
			JWK jwk = JwkUtil.createEncrptionJWK(encryptionCredential, id, jweHeader.getKeyID());
			if (jwk == null) {
				log.debug("Could not create encryption JWK for={}, skipping encryption", id);
				var nimbusJwtEncoder = new NimbusJwtEncoder(jwkSource);
				return nimbusJwtEncoder.encode(parameters);
			}

			var jwe = JwtUtil.encryptJwt(jweHeader, payload, jwk);

			return new Jwt(jwe, claims.getIssuedAt(), claims.getExpiresAt(), jweHeader.toJSONObject(), jwtClaimsSet.getClaims());
		} catch (JOSEException e) {
			throw new TechnicalException(String.format("Unexpected JOSE exception %s", e.getMessage()), e);
		}
	}

	public static void validateToken(String token) {
		if (token == null) {
			return;
		}

		// 1 = OPAQUE_TOKEN_PARTS
		// 2 or 3 = JWT_TOKEN_PARTS https://datatracker.ietf.org/doc/html/rfc7519#section-7.2
		// 5 = JWE_TOKEN_PARTS https://datatracker.ietf.org/doc/html/rfc7516#section-9
		var parts = token.split("\\.", -1);
		int length = parts.length;
		if (length < OPAQUE_TOKEN_PARTS || length > JWE_TOKEN_PARTS) {
			throw new TechnicalException(String.format("Invalid JWT token structure token: %s", StringUtil.clean(token)));
		}

		// Validating our own tokens generated by spring-security to make sure we do not have SQL injection when querying our database.
		for (String part : parts) {
			for (char c : part.toCharArray()) {
				if (!Character.isLetterOrDigit(c) && c != '-' && c != '_') {
					throw new TechnicalException(String.format("JWT token contains illegal characters token: %s", StringUtil.clean(token)));
				}
			}
		}
	}

	public static boolean isJwt(String token) {
		return token != null && token.matches("[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+");
	}

	public static String getRecommendedEncryptionMethod(String alg) {
		if (alg == null) {
			return null;
		}

		return switch (alg) {
			case "RSA1_5" -> EncryptionMethod.A128CBC_HS256.getName();
			case "ECDH-ES+A128KW", "A128KW", "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW" -> EncryptionMethod.A128GCM.getName();
			case "ECDH-ES+A192KW", "A192KW" -> EncryptionMethod.A192GCM.getName();
			default ->
					// "RSA-OAEP", "RSA-OAEP-256", "ECDH-ES", "ECDH-ES+A256KW", "A256KW", "dir"
					EncryptionMethod.A256GCM.getName();
		};
	}
}
