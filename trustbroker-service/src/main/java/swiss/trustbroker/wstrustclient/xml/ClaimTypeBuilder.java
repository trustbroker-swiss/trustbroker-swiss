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

package swiss.trustbroker.wstrustclient.xml;

import org.opensaml.soap.wstrust.impl.AbstractWSTrustObjectBuilder;

public class ClaimTypeBuilder extends AbstractWSTrustObjectBuilder<ClaimType> {

	public ClaimType buildObject() {
		return buildObject(ClaimType.ELEMENT_NAME);
	}

	public ClaimType buildObject(final String namespaceURI, final String localName, final String namespacePrefix) {
		return new ClaimTypeImpl(namespaceURI, localName, namespacePrefix);
	}

}
