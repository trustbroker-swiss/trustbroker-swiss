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

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Quality of Authentication (QoA) configuration.
 *
 * @see swiss.trustbroker.mapping.service.QoaMappingService
 */
@XmlRootElement(name = "Qoa")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Qoa implements Serializable {

	/**
	 * Enable QoA enforcement.
	 * <br/>
	 * Default: false
	 *
	 * @since 1.9.0
	 */
	@XmlAttribute(name = "enforce")
	@Builder.Default
	private Boolean enforce = Boolean.FALSE;

	/**
	 * Enable mapping of outbound QoA.
	 * <br/>
	 * Default: true
	 *
	 * @since 1.9.0
	 */
	@XmlAttribute(name = "mapOutbound")
	@Builder.Default
	private Boolean mapOutbound = Boolean.TRUE;

	/**
	 * Send single QoA in response (to RP).
	 * <br/>
	 * Relevant for comparison EXACT - send maximum matching value instead.
	 * <br/>
	 * Default: true
	 *
	 * @since 1.9.0
	 */
	@XmlAttribute(name = "singleQoaResponse")
	@Builder.Default
	private Boolean singleQoaResponse = Boolean.TRUE;

	/**
	 * Comparison type.
	 *
	 * @since 1.9.0
	 */
	@XmlAttribute(name = "comparison")
	private QoaComparison comparison;

	/**
	 * List of SAML AuthnContextClassRef entries.
	 * <br/>
	 * If the RP does not send and AuthnRequest class references, the configured context classes are added to the
	 * CP-side AuthnRequest to let the CP deal with the QoA requirements of the RP.
	 */
	@XmlElement(name = "ACClass")
	@Builder.Default
	private List<AcClass> classes = new ArrayList<>();

	@JsonIgnore
	public boolean isEnforce() {
		return Boolean.TRUE.equals(enforce);
	}

	@JsonIgnore
	public boolean isMapOutbound() {
		return Boolean.TRUE.equals(mapOutbound);
	}

	@JsonIgnore
	public boolean useSingleQoaInResponse() {
		return Boolean.TRUE.equals(singleQoaResponse);
	}

}
