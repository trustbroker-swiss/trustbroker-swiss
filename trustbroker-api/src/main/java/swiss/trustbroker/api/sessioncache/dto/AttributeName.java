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
import java.util.Objects;

/**
 * Addressing of an attribute via name and/or namespace URI.
 */
public interface AttributeName {

	/**
	 * @return Audit and IDM relevant name, unique
 	 */
	public String getName();

	/**
	 * @return Known external CP attributes we just document here - used when we cannot use namespaceUri due to semantics
	 * (can be null)
	 */
	public String getAltName();

	/**
	 * @return SAML attribute, value must be unique to prevent auditing to not display wrong short names
	 */
	public String getNamespaceUri();

	/**
	 * @return OIDC standard claim, served when standard claim mapping is enabled and no configured attribute has it in oidcNames
	 */
	public List<String> getOidcNameList();

	// false for null name
	default boolean equalsByNameOrNamespace(String name) {
		return name != null && (Objects.equals(getName(), name) || Objects.equals(getNamespaceUri(), name));
	}

}
