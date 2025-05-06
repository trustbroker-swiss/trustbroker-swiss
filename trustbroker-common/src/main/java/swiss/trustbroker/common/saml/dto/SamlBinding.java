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

package swiss.trustbroker.common.saml.dto;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.common.xml.SAMLConstants;
import swiss.trustbroker.common.exception.RequestDeniedException;

@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Getter
@Slf4j
public enum SamlBinding {
	POST(SAMLConstants.SAML2_POST_BINDING_URI),
	REDIRECT(SAMLConstants.SAML2_REDIRECT_BINDING_URI),
	ARTIFACT(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);

	private final String bindingUri;

	public boolean compatibleWithRequestedBinding(SamlBinding requestedBinding) {
		if (requestedBinding == null || this == requestedBinding) {
			log.debug("Correct response binding={} for requested protocolBinding={}", this, requestedBinding);
			return true;
		}
		if (requestedBinding == REDIRECT && this == POST) {
			// Response is never sent as redirect (length restrictions)
			log.info("Accepting responseBinding={} for requested protocolBinding={}", this, requestedBinding);
			return true;
		}
		log.debug("Wrong responseBinding={} for requested protocolBinding={}", this, requestedBinding);
		return false;
	}

	public static SamlBinding of(String protocolBinding) {
		if (protocolBinding == null) {
			return null;
		}
		for (var binding : values()) {
			if (binding.bindingUri.equals(protocolBinding)) {
				return binding;
			}
		}
		throw new RequestDeniedException(String.format("Unsupported protocolBinding=%s", protocolBinding));
	}
}
