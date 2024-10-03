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

package swiss.trustbroker.api.sessioncache.dto;

import java.util.List;
import java.util.Map;

public interface CpResponseData {

	// identity data

	String getIssuerId();

	String getNameId();

	public String getHomeName();

	String getClientName();

	// IDP attributes

	Map<AttributeName, List<String>> getAttributeMap();

	List<String> getAttributes(String name);

	String getAttribute(String name);

	// IDM attributes

	Map<AttributeName, List<String>> getUserDetailMap();

	List<String> getUserDetails(String name);

	String getUserDetail(String name);

	// derived attributes

	Map<AttributeName, List<String>> getPropertyMap();

	List<String> getProperties(String name);

	String getProperty(String name);

}
