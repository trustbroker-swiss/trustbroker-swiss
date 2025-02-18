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
 * This class allows configuring policies per CP/RP as opposed to SecurityChecks on a global level.
 */
@XmlRootElement(name = "SecurityPolicies")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityPolicies implements Serializable {

	/**
	 * Allow to disable signature check for incoming SAML AuthnRequests.
	 */
	@XmlAttribute(name = "requireSignedAuthnRequest")
	@Builder.Default
	private Boolean requireSignedAuthnRequest = Boolean.TRUE;

	/**
	 * Allow to disable signature check for incoming LogoutRequests.
	 */
	@XmlAttribute(name = "requireSignedLogoutRequest")
	@Builder.Default
	private Boolean requireSignedLogoutRequest = Boolean.TRUE;

	/**
	 * Flag allows to enforce signed SAML responses from CP required for maximum security to assert integrity of the incoming
	 * message and assertion. There is no requireSignedAssertion yet as this data structure is the actual data to trust.
	 * The check can therefore not be disabled for security reasons.
	 * <br/>
	 * Overrides global SecurityChecks
	 */
	@XmlAttribute(name = "requireSignedResponse")
	private Boolean requireSignedResponse;

	/**
	 * Overrides global SecurityChecks
 	 */
	@XmlAttribute(name = "requireAudienceRestriction")
	private Boolean requireAudienceRestriction;

	/**
	 * Overrides the global <code>tokenLifetimeSec</code> for CP response AuthnInstant checks.
	 * <br/>
	 * Defaults to 60 minutes, override if needed.
	 * This is quite long time to transfer a SAML token from the issuer to its consumer to establish a relation between a user and
	 * the consuming RP. Tje problem is that some components cache the token and transfer it later.
	 */
	@XmlAttribute(name = "notOnOrAfterSeconds")
	@Builder.Default
	private Integer notOnOrAfterSeconds = 3600;

	/**
	 * Overrides the global <code>notOnOrAfterSeconds</code> for conditions <code>notOnOrAfter</code> if greater than zero.
	 */
	@XmlAttribute(name = "audienceNotOnOrAfterSeconds")
	private Integer audienceNotOnOrAfterSeconds;

	/**
	 * If CP returns AuthnContext of value less than that, no SSO session is created.
	 */
	@XmlAttribute(name = "ssoMinQoaLevel")
	private Integer ssoMinQoaLevel;

	/**
	 * Some claims providers are not sending well-formed valid XML and therefore are blocked by XTB. The schema check can be
	 * disabled lowering the security barrier and let OpenSAML deal with the data directly.
	 */
	@XmlAttribute(name = "validateXmlSchema")
	@Builder.Default
	private Boolean validateXmlSchema = Boolean.TRUE;

	/**
	 * Control CP AuthnRequest scopes and RP Attribute OriginalIssuer.
	 * Defaults to null as RP and CP side default behavior differs
	 */
	@XmlAttribute(name = "delegateOrigin")
	private Boolean delegateOrigin;
}
