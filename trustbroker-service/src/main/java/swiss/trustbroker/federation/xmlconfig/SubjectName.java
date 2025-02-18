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

package swiss.trustbroker.federation.xmlconfig;

import java.io.Serializable;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlRootElement;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * The SubjectName map allows to pick an attribute as a mapped subject nameId from the following sources in this order:
 * <ol>
 *     <li>AttributesSelection</li>
 *     <li>>UserDetailsSelection</li>
 *     <li>PropertiesSelection</li>
 * </ol>
 * If the issuer is defined, the picking is done per CP. If the issuer is null, the configuration applies to all CPs.
 * <br/>
 * If the attribute...
 * <ul>
 *     <li>is found: CPResponse.nameID is set before the OnResponse hook (RP side) / BeforeIdm hook (CP side)
 *     and an INFO log states the mapping/</li>
 *     <li>is not found: An INFO log states what has been preserved.</li>
 * </ul>
 */
@XmlRootElement(name = "SubjectName")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SubjectName implements Serializable {

	/**
	 * Matched against the CP issuer.
	 * <br/>
	 * Only makes sense in an RP configuration, thus for a CP you only configure a single <code>SubjectName</code> without issuer.
	 */
	@XmlAttribute(name = "issuer")
	private String issuer;

	/**
	 * Subject Name ID attribute name.
	 */
	@XmlAttribute(name = "source")
	private String source;

	/**
	 * Subject Name ID format.
	 */
	@XmlAttribute(name = "format")
	private String format;

	public boolean isIssuerMatching(String cpIssuerId) {
		return issuer == null || issuer.equals(cpIssuerId);
	}

}
