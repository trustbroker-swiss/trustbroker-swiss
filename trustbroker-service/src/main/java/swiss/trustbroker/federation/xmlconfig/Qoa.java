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
import java.util.ArrayList;
import java.util.List;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Quality of Authentication (QoA) configuration.
 *
 * @see swiss.trustbroker.api.qoa.service.QualityOfAuthenticationService
 */
@XmlRootElement(name = "Qoa")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Qoa implements Serializable {

	/**
	 * List of SAML AuthnContextClassRef entries.
	 * <br/>
	 * If the RP does not send and AuthnRequest class references, the configured context classes are added to the
	 * CP-side AuthnRequest to let the CP deal with the QoA requirements of the RP.
	 */
	@XmlElement(name = "ACClass")
	@Builder.Default
	private List<String> classes = new ArrayList<>();

}
