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

package swiss.trustbroker.api.idm.service;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import swiss.trustbroker.api.idm.dto.IdmRequest;
import swiss.trustbroker.api.idm.dto.IdmRequests;
import swiss.trustbroker.api.idm.dto.IdmResult;
import swiss.trustbroker.api.relyingparty.dto.RelyingPartyConfig;
import swiss.trustbroker.api.sessioncache.dto.CpResponseData;

/**
 * Interface for accessing an IDM service (e.g. via LDAP).
 * <br/>
 * An implementation can be configured via Spring @Value binding or by injecting swiss.trustbroker.config.TrustbrokerProperties
 * and using swiss.trustbroker.config.dto.IdmConfig (${trustbroker.config.idm}).
 *
 * Breaking changes:
 * <ul>
 *     <li>With 1.8.0 getAttributesFromIdm renamed to getAttributes.</li>
 * </ul> 
 */
public interface IdmService {

	/**
	 * @param relyingPartyConfig   Data from the request (not null)
	 * @param cpResponse           Data from the CP response (not null)
	 * @param idmRequests          Defines the requests to be performed by this call to query the IDM.
	 * @param statusPolicyCallback callback for status policy enforcement
	 * @return Optional.empty if this service does not apply for these queries. A non-null result otherwise
	 * 
	 * @since 1.8.0
	 */
	Optional<IdmResult> getAttributes(RelyingPartyConfig relyingPartyConfig, CpResponseData cpResponse,
			IdmRequests idmRequests, IdmStatusPolicyCallback statusPolicyCallback);

	/**
	 * Implements getAttributes as well but signals, that the IDM data is fetched based on a federated login
	 * for the first time and therefore might need additional auditing (write operations on an otherwise read-only access).
	 * 
	 * @since 1.8.0
	 */
	default Optional<IdmResult> getAttributesAudited(RelyingPartyConfig relyingPartyConfig, CpResponseData cpResponse,
			IdmRequests idmRequests, IdmStatusPolicyCallback statusPolicyCallback) {
		return getAttributes(relyingPartyConfig, cpResponse, idmRequests, statusPolicyCallback);
	}

	/**
	 * @param idmRequests        Defines the requests to be performed by the call to query the IDM.
	 * @return ClientExtId if defined in idmRequests and relevant for this service.
	 */
	default Optional<String> getClientExtId(IdmRequests idmRequests) {
		return Optional.empty();
	}

	/**
	 * @param idmRequests Defines the requests to be performed by this call to query the IDM.
	 * @return IdmRequest sorted in a suitable way, e.g. by name, if applicable for this service, otherwise unmodified list from
	 * idmRequests or empty Optional
	 */
	default List<IdmRequest> sortIdmRequests(IdmRequests idmRequests) {
		return idmRequests != null ? idmRequests.getQueryList() : Collections.emptyList();
	}
}
