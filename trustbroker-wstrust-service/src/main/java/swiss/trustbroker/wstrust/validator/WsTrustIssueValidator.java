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

package swiss.trustbroker.wstrust.validator;

import java.time.Clock;
import java.util.Optional;

import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.soap.wssecurity.BinarySecurityToken;
import org.opensaml.soap.wstrust.RequestSecurityToken;
import org.opensaml.soap.wstrust.RequestType;
import org.springframework.stereotype.Component;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.wstrust.dto.WsTrustValidationResult;

/**
 * Validator for WS-Trust ISSUE requests.
 */
@Component
@Slf4j
public class WsTrustIssueValidator extends WsTrustBaseValidator {

	public WsTrustIssueValidator(
			TrustBrokerProperties trustBrokerProperties, RelyingPartySetupService relyingPartySetupService, Clock clock) {
		super(trustBrokerProperties, relyingPartySetupService, clock);
	}

	@Override
	public boolean applies(RequestType requestType) {
		return RequestType.ISSUE.equals(requestType.getURI());
	}

	@Override
	public WsTrustValidationResult validate(RequestSecurityToken requestSecurityToken, Assertion headerAssertion,
			BinarySecurityToken securityToken) {
		log.debug("RSTR ISSUE request - assertion is in header");
		if (securityToken != null) {
			log.info("RSTR with requestType='{}' ignoring header security token", RequestType.ISSUE);
		}
		validateAssertion(headerAssertion, null, Optional.empty());
		return new WsTrustValidationResult(headerAssertion, true, null);
	}
}
