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

import java.util.List;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.extern.slf4j.Slf4j;
import swiss.trustbroker.common.exception.TechnicalException;

/**
 * Util class for Jose JWK.
 */
@Slf4j
public class JwkUtil {

	private JwkUtil() {}

	public static String getKeyIdFromJwkSource(JWKSource<SecurityContext> jwkSource) {
		var jwks = getJwkListFromJwkSource(jwkSource);
		if (!jwks.isEmpty()) {
			// Here we rely on the order returned by our own RotateJwkSource, which sends the OLDEST first.
			// I.e. we pick the OLDEST valid key to give calling applications the maximum time to re-fetch our metadata.
			// Some applications do this only at intervals configured on their side.
			var kid = jwks.stream()
					.map(JWK::getKeyID)
					.findFirst()
					.orElseThrow(() -> new TechnicalException("kid not found"));
			log.debug("Picked first JWK with kid={}", kid);
			return kid;
		}
		log.debug("No JWKs found in JWKSource");
		return null;
	}

	public static List<JWK> getJwkListFromJwkSource(JWKSource<SecurityContext> jwkSource) {
		try {
			var jwkSelector = new JWKSelector(new JWKMatcher.Builder().build());
			return jwkSource.get(jwkSelector, null);
		}
		catch (KeySourceException e) {
			throw new TechnicalException(String.format("Failed to select the JWK(s) msg=%s", e.getMessage()), e);
		}
	}
}
