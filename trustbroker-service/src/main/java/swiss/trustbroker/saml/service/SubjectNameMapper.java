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

package swiss.trustbroker.saml.service;

import java.util.Optional;

import lombok.extern.slf4j.Slf4j;
import swiss.trustbroker.federation.xmlconfig.CounterParty;
import swiss.trustbroker.federation.xmlconfig.SubjectName;
import swiss.trustbroker.saml.dto.CpResponse;

@Slf4j
class SubjectNameMapper {

	private SubjectNameMapper() {}

	static void adjustSubjectNameId(CpResponse cpResponse, CounterParty counterParty) {
		var nameIdMappings = counterParty.getSubjectNameMappings();
		var reason = "No matching mapping found";
		var cpIssuer = cpResponse.getIssuerId();
		Optional<SubjectName> subjectMapping = Optional.empty();
		if (nameIdMappings != null && nameIdMappings.getSubjects() != null) {
			if (!cpResponse.hasOriginalNameId() && nameIdMappings.getPreserve()) {
				reason = "NameID already set before"; // i.e. by a groovy script
			}
			else {
				subjectMapping = nameIdMappings.getSubjects()
						.stream()
						.filter(m -> m.isIssuerMatching(cpIssuer) && mapSubject(m, counterParty, cpResponse))
						.findFirst();
			}
		}
		if (subjectMapping.isEmpty()) {
			log.info("Preserve federation principal for {} issuer={} cpIssuer={} cpNameId={} rpNameId={} using format={}: {}",
					counterParty.getShortType(), counterParty.getId(), cpIssuer, cpResponse.getOriginalNameId(),
					cpResponse.getNameId(), cpResponse.getNameIdFormat(), reason);
		}
	}

	private static boolean mapSubject(SubjectName subjectMapping, CounterParty counterParty, CpResponse cpResponse) {
		var cpIssuer = cpResponse.getIssuerId();
		var nameIdSource = subjectMapping.getSource();
		var claimSource = "AttributesSelection";
		var nameId = cpResponse.getAttribute(nameIdSource);
		if (nameId == null) {
			claimSource = "UserDetailsSelection";
			nameId = cpResponse.getUserDetail(nameIdSource);
		}
		if (nameId == null) {
			claimSource = "PropertiesSelection";
			nameId = cpResponse.getProperty(nameIdSource);
		}
		if (nameId != null) {
			// also allow to adjust the format (relevant for some RPs)
			var nameIdFormat = subjectMapping.getFormat();
			if (nameIdFormat == null) {
				nameIdFormat = cpResponse.getNameIdFormat();
			}
			cpResponse.setNameId(nameId);
			cpResponse.setNameIdFormat(nameIdFormat);
			log.info("Change federation principal from cpIssuer={} cpNameId={} to {} issuer={} rpNameId={}"
							+ " using source='{} ({})' format={}",
					cpIssuer, cpResponse.getOriginalNameId(), counterParty.getShortType(), counterParty.getId(),
					cpResponse.getNameId(), nameIdSource, claimSource, nameIdFormat);
			return true;
		}
		log.debug("Preserve federation principal for {} issuer={} cpIssuer={} cpNameId={} rpNameId={}"
						+ " using format={} because source={} is undefined",
				counterParty.getShortType(), counterParty.getId(), cpIssuer, cpResponse.getOriginalNameId(),
				cpResponse.getNameId(), cpResponse.getNameIdFormat(), nameIdSource);
		return false;
	}

}
