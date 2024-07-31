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
package swiss.trustbroker.api.accessrequest.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

/**
 * Result of access request.
 */
@Data
@Builder
@AllArgsConstructor(staticName = "of")
public class AccessRequestResult {

	/**
	 * IDM data needs to be re-loaded due to onboarding.
	 */
	private final boolean reloadIdmData;

	/**
	 * Session was changed and needs to be stored.
	 */
	private final boolean retainSession;

	/**
	 * Redirect URL for performing the access request.
	 */
	private final String redirectUrl;

}
