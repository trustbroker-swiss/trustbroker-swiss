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
import jakarta.xml.bind.annotation.XmlValue;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Home Name configuration.
 */
@XmlRootElement(name = "HomeName")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class HomeName implements Serializable {

	/**
	 * Overridden by value.
	 *
	 * @see HomeName#getValue()
	 */
	@XmlAttribute(name = "value")
	private String attrValue;

	/**
	 * The homeName is usually consumed from the home name attribute and identifies the CP attribute to consume the
	 * CP identity from. If not specified or not provided by CP the SAML Response Subject NameID is used.
	 */
	@XmlAttribute(name = "reference")
	private String reference;

	/**
	 * The configuration is optional and provides a static value, when the e-id based CPs are not sending the attribute
	 * in the CP Attributes already or the value is computed from the CP SAML Response mainly for compatibility reasons,
	 * see <strong>GeneralDeriveHomeName.groovy</strong> for the special handling of this attribute.
	 */
	@XmlValue
	private String value;

}
