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

package swiss.trustbroker.federation.service;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.function.Predicate;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.dto.ConfigElementStatus;
import swiss.trustbroker.federation.dto.ConfigStatus;
import swiss.trustbroker.federation.dto.ConfigStatusData;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.ValidationStatus;

/**
 * Service for checking the configuration status.
 */
@Service
@AllArgsConstructor
@Slf4j
public class XmlConfigStatusService {

	private final RelyingPartyDefinitions relyingPartyDefinitions;

	public ConfigStatusData getConfigStatus() {
		var relyingParties = relyingPartyDefinitions.getRelyingPartySetup().getUnfilteredRelyingParties();
		var relyingPartyStatuses = getStatuses(relyingParties,
				RelyingParty::getId, isRpInvalid(), RelyingParty::getValidationStatus);
		var claimsParties = relyingPartyDefinitions.getClaimsProviderSetup().getUnfilteredClaimsParties();
		var claimsProviderStatuses = getStatuses(claimsParties,
				ClaimsParty::getId, isCpInvalid(), ClaimsParty::getValidationStatus);
		var status = getOverallStatus(relyingParties, claimsParties, relyingPartyStatuses, claimsProviderStatuses);
		return ConfigStatusData.builder()
							   .status(status)
							   .relyingParties(relyingPartyStatuses)
							   .claimsProviders(claimsProviderStatuses)
							   .build();
	}

	private static Predicate<ClaimsParty> isCpInvalid() {
		return cp -> !cp.isValid() || cp.initializedValidationStatus().hasErrors();
	}

	private static Predicate<RelyingParty> isRpInvalid() {
		return rp -> !rp.isValid() || rp.initializedValidationStatus().hasErrors();
	}

	private static ConfigStatus getOverallStatus(List<RelyingParty> relyingParties, List<ClaimsParty> claimsParties,
			List<ConfigElementStatus> relyingPartyStatuses, List<ConfigElementStatus> claimsProviderStatuses) {
		if (relyingParties.isEmpty() || claimsParties.isEmpty()) {
			return ConfigStatus.ERROR;
		}
		if (relyingPartyStatuses.isEmpty() && claimsProviderStatuses.isEmpty()) {
			return ConfigStatus.OK;
		}
		return ConfigStatus.WARN;
	}

	private static <T> List<ConfigElementStatus> getStatuses(List<T> elements,
			Function<T, String> idAccessor, Predicate<T> invalidCheck,
			Function<T, ValidationStatus> statusAccessor) {
		var result = new ArrayList<ConfigElementStatus>();
		for (var element : elements) {
			if (invalidCheck.test(element)) {
				result.add(ConfigElementStatus.builder()
											  .id(idAccessor.apply(element))
											  .errors(statusAccessor.apply(element).getErrors())
											  .build());
			}
		}
		return result;
	}
}
