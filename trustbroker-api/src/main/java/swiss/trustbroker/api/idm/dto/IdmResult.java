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
package swiss.trustbroker.api.idm.dto;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;

/**
 * Result of IDM lookup.<br/>
 * <ul>
 *     <li><strong>userDetails</strong> are values from the source.<br/>
 *     They are filtered via RelyingParty UserDetailsSelection.</li>
 *     <li><strong>properties</strong> are values derived from the attributes.<br/>
 *     They are filtered via RelyingParty PropertiesSelection.</li>
 * </ul>
 * The counts of the two before filtering are returned separately.
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class IdmResult {

	@Builder.Default
	private Map<AttributeName, List<String>> userDetails = new HashMap<>();

	private int originalUserDetailsCount;

	@Builder.Default
	private Map<AttributeName, List<String>> properties = new HashMap<>();

	private int originalPropertiesCount;

}
