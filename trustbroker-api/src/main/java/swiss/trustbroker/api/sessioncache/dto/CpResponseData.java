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

/**
 * Response from CP.
 */
public interface CpResponseData {

	// identity data

	String getIssuerId();

	String getNameId();

	public String getHomeName();

	String getClientName();

	// CP attributes

	/**
	 * @return never null, but may be unmodifiable.
	 */
	Map<AttributeName, List<String>> getAttributeMap();

	/**
	 * @param name
	 * @return may return null to distinguish between empty list of values and undefined.
	 */
	List<String> getAttributes(String name);

	String getAttribute(String name);

	// IDM attributes

	/**
	 * @return never null, but may be unmodifiable.
	 */
	Map<AttributeName, List<String>> getUserDetailMap();

	/**
	 * @param name
	 * @return may return null to distinguish between empty list of values and undefined.
	 */
	List<String> getUserDetails(String name);

	String getUserDetail(String name);

	List<String> getUserDetails(String name, String source);

	String getUserDetail(String name, String source);

	// derived attributes

	/**
	 * @return never null, but may be unmodifiable.
	 */
	Map<AttributeName, List<String>> getPropertyMap();

	/**
	 * @param name
	 * @return may return null to distinguish between empty list of values and undefined.
	 */
	List<String> getProperties(String name);

	String getProperty(String name);

	List<String> getProperties(String name, String source);

	String getProperty(String name, String source);

}
