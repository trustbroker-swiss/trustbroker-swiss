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

package swiss.trustbroker.oidc.client.controller;

import java.util.Map;

import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import swiss.trustbroker.common.exception.ErrorCode;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.oidc.client.service.AuthorizationCodeFlowService;
import swiss.trustbroker.sessioncache.service.StateCacheService;
import swiss.trustbroker.util.ApiSupport;

/**
 * OIDC client side controller accepting responses from an OIDC CP.
 * 
 * Note: With 1.9.0 this feature is still unfinished, some parts to be completed in the NEXT release marked as such.
 */
@Controller
@AllArgsConstructor
@Slf4j
public class OidcClientController {

	private final AuthorizationCodeFlowService authorizationCodeFlowService;

	private final RelyingPartySetupService relyingPartySetupService;

	private final StateCacheService stateCacheService;

	@GetMapping({ ApiSupport.OIDC_RESPONSE_URL, ApiSupport.OIDC_RESPONSE_URL + "/{realm}"})
	public void authorizationCodeResponse(HttpServletResponse httpServletResponse,
			@PathVariable(name = "realm", required = false) String realm,
			@RequestParam(name = "state", required = false) String state,
			@RequestParam(name = "code", required = false) String code,
			@RequestParam(name = "error", required = false) String error,
			@RequestParam(name = "error_description", required = false) String errorDescription,
			@RequestParam(name = "error_uri", required = false) String errorUri) {
		log.info("Received authorization code response for realm={} state={} code=***", realm, state);
		if (state == null) {
			throw new RequestDeniedException(
					String.format("Missing state in OIDC authorization code response for realm=%s", realm));
		}
		var stateData = stateCacheService.findMandatoryValidState(state, OidcClientController.class.getSimpleName());
		if (error != null) {
			// NEXT: continue flow AssertionConsumerService.handleFailedCpResponse -> SAML/OIDC handling to be refactored
			throw new RequestDeniedException(
					String.format("Error=%s description=%s uri=%s OIDC authorization code response for realm=%s",
					error, errorDescription, errorUri, realm));
		}

		log.info("Received authorization code response for realm={} state={} code=***", realm, state);
		if (code == null) {
			throw new RequestDeniedException(
					String.format("Missing code in OIDC authorization code response for realm=%s state=%s", realm, state));
		}
		var claimsParty = relyingPartySetupService.getClaimsProviderSetupByIssuerId(stateData.getCpIssuer(), null);
		authorizationCodeFlowService.handleCpResponse(realm, code, claimsParty, stateData);
		stateCacheService.save(stateData, OidcClientController.class.getSimpleName());
		// NEXT: continue flow AssertionConsumerService.handleSuccessCpResponse -> SAML/OIDC handling to be refactored
		// until then throw exception to get some UI feedback
		throw new RequestDeniedException("OIDC response successful - return to AssertionConsumerService not yet implemented");
	}

	@PostMapping(path = { ApiSupport.OIDC_RESPONSE_URL, ApiSupport.OIDC_RESPONSE_URL + "/{realm}"},
			consumes = MediaType.APPLICATION_JSON_VALUE)
	public void tokenResponse(
			@PathVariable(name = "realm", required = false) String realm,
			@RequestBody Map<String, Object> json) {
		log.info("Received token response for realm={} token=***", realm);
		// NEXT: proper token type and handling via authorizationCodeFlowService
	}

}
