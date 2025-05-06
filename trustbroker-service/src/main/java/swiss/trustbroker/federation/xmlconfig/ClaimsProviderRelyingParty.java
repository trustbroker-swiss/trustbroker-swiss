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

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlRootElement;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import swiss.trustbroker.api.homerealmdiscovery.attributes.HrdClaimsProviderToRelyingPartyMapping;

/**
 * Configuration for CP mapped to an RP.
 *
 * @see swiss.trustbroker.api.homerealmdiscovery.service.HrdService
 */
@XmlRootElement(name = "ClaimsProvider")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ClaimsProviderRelyingParty implements Serializable, HrdClaimsProviderToRelyingPartyMapping {

	/**
	 * References the issuer ID of the CP.
	 *
	 * @see ClaimsProvider#getId()
	 */
	@XmlAttribute(name = "id")
	private String id;

	/**
	 * Allow pre-configuration of ClaimsProviderMappings with enabled or disabled ClaimsParty in profiles and only pick
	 * them per relying party in setup.
	 * Default: Unset value signals an enabled claims party and ignoring entries with the same id in the profile.
	 *
	 * @since 1.9.0
	 */
	@XmlAttribute(name = "enabled")
	private Boolean enabled;

	/**
	 * Indicates the order of display in the UI. Special values:
	 * <ol>
	 *     <li>less or equal 0 - do not show in UI</li>
	 *     <li>1xx - first priority CPs (displayed larger, ordered numerically)</li>
	 *     <li>2xx - second priority CPs (displayed larger, ordered numerically)</li>
	 *     <li>3xx - third priority CPs (displayed smalled, ordered numerically)</li>
	 * </ol>
	 * Default: ordered of definition in the XML
	 *
	 * @since 1.9.0
	 */
	@XmlAttribute(name = "order")
	private Integer order;

	/**
	 * Show banner if tile is enabled.
	 *
	 * @since 1.9.0
	 */
	@XmlAttribute(name = "banner")
	private String banner;

	/**
	 * A comma separated list of network identifiers. When computing the HRD screen the incoming loadbalancer HTTP Header
	 * Client_Network (is considered to filter out CPs that are not defined on the incoming network, mainly:
	 * <ul>
	 *     <li>INTRANET (intranet)</li>
	 *     <li>INTERNET (external networks)</li>
	 * </ul>
	 */
	@XmlAttribute(name = "clientNetworks")
	private String clientNetworks;

	/**
	 * By providing a relying party ID on the HRD declaration, it's not necessary anymore to copy and paste entire RP
	 * definition files just to be able to automatically selecting an RP without showing a HRD selection screen.
	 * The relyingPartyAlias can refer to these three inputs:
	 * <ul>
	 *     <li>SAML AuthnRequest.Issuer ID</li>
	 *     <li>SAML AuthnRequest.ProviderName</li>
	 *     <li>OIDC client_id</li>
	 * </ul>
	 * The HRD entries with a relyingPartyAlias attribute are not shown on the HRD screen but are used to directly dispatch
	 * towards the CP when an RP with this issuer ID comes along.
	 * <br/>
	 * If no alias matches through and no HRD entries without an alias remain, all the tiles are displayed through.
	 */
	@XmlAttribute(name = "relyingPartyAlias")
	private String relyingPartyAlias;

	public final boolean isValidForNetwork(String network) {
		return network == null
				|| clientNetworks == null
				|| clientNetworks.contains(network);
	}

	public final boolean isMatchingRelyingPartyAlias(String rpIssuer) {
		return relyingPartyAlias != null && relyingPartyAlias.equals(rpIssuer);
	}

	public static ClaimsProviderRelyingParty of(HrdClaimsProviderToRelyingPartyMapping mapping) {
		if (mapping instanceof ClaimsProviderRelyingParty cpRp) {
			return cpRp;
		}
		if (mapping == null) {
			return null;
		}
		return ClaimsProviderRelyingParty.builder()
				.id(mapping.getId())
				.clientNetworks(mapping.getClientNetworks())
				.relyingPartyAlias(mapping.getRelyingPartyAlias())
				.build();
	}

	@JsonIgnore
	public boolean isDisplayed() {
		// Old HRD config does not use order and CPs with alias are never displayed
		return (order == null || order > 0);
	}

}
