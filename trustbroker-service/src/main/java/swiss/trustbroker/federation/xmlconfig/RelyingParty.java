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
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.commons.collections.ListUtils;
import org.apache.commons.lang3.StringUtils;
import org.opensaml.security.credential.Credential;
import swiss.trustbroker.api.relyingparty.dto.RelyingPartyConfig;
import swiss.trustbroker.common.saml.dto.SamlBinding;
import swiss.trustbroker.common.saml.dto.SignatureParameters;
import swiss.trustbroker.util.PropertyUtil;

/**
 * This class describes the configuration of a relying party (RP).
 * <br/>
 * The following sources of attributes to be passed to the RP exist:
 * <ul>
 *     <li>Attributes definitions (from CP)</li>
 * 	   <li>UserDetails definitions (from IDM)</li>
 * 	   <li>Properties definitions (computed by XTB or in Scripts)</li>
 * </ul>
 * <br/>
 * RP profiles are configuration templates for RP setups that reflect a common pattern used by multiple RPs.
 */
@XmlRootElement(name = "RelyingParty")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RelyingParty implements Serializable, RelyingPartyConfig {

	@XmlAttribute(name = "id")
	private String id;

	@XmlTransient
	private String unaliasedId;

	/**
	 * Flag to enable/disable this RP.
	 * <br/>
	 * Default is true.
	 */
	@XmlAttribute(name = "enabled")
	@Builder.Default
	private String enabled = FeatureEnum.TRUE.name(); // String to support 'true' and 'false' for consistency

	@XmlAttribute(name = "base")
	private String base;

	/**
	 * ClientName is the access tenant identifier (somewhat a short form of the relying party ID)
	 * applied to all <pre>%clientname%</pre> placeholders in the configuration, specifically the attributes as listed
	 * above.
	 */
	@XmlElement(name = "ClientName")
	private String clientName;

	/**
	 * We introduce the billing field, so we can start make some trials adding it to the config. We might need to move it
	 * to the access request application section later if RP-ID is not 1:1 related to billingId.
	 * The value is currently only used in the XTB auditing.
	 */
	@XmlElement(name = "BillingId")
	private String billingId;

	/**
	 * Primary key of the IDM client identifying an access tenant.
	 */
	@XmlElement(name = "ClientExtId")
	private String clientExtId;

	// endpoints

	/**
	 * Assertion consumer service URL authorized to access XTB federation services for this RP.
	 */
	@XmlElement(name = "ACWhitelist")
	private AcWhitelist acWhitelist;

	// access control

	/**
	 * For verification and signing. For signing the SignerKeystore declared on is (re-)used on the CP side.
	 *
	 * @see ClaimsParty#getCertificates()
	 */
	@XmlElement(name = "Certificates", required = false)
	private Certificates certificates;

	/**
	 * Global security policy overrides for this RP.
	 */
	@XmlElement(name = "SecurityPolicies")
	private SecurityPolicies securityPolicies;

	/**
	 * OIDC client configuration for this RP.
	 */
	@XmlElement(name = "Oidc")
	private Oidc oidc;

	/**
	 * SAML protocol configuration for this RP.
	 */
	@XmlElement(name = "Saml")
	private Saml saml;

	// feature flags

	/**
	 * Announcement configuration for this RP.
	 */
	@XmlElement(name = "Announcements")
	private AnnouncementRpConfig announcement;

	/**
	 * SSO configuration for this RP.
	 */
	@XmlElement(name = "SSO")
	private Sso sso;

	// HRD

	/**
	 * List of CPs mapped to this RP.
	 */
	@XmlElement(name = "ClaimsProviderMappings")
	private ClaimsProviderMappings claimsProviderMappings;

	/**
	 * Subject Name ID mappings for this RP.
	 */
	@XmlElement(name = "SubjectNameMappings")
	private SubjectNameMappings subjectNameMappings;

	// processing model

	/**
	 * QoA configurations for this RP.
	 */
	@XmlElement(name = "Qoa")
	private Qoa qoa;

	/**
	 * Error flow policies for this RP.
	 */
	@XmlElement(name = "FlowPolicies")
	private FlowPolicies flowPolicies;

	/**
	 * AccessRequest configuration for this RP.
	 */
	@XmlElement(name = "AccessRequest")
	private AccessRequest accessRequest;

	/**
	 * RP side attribute selection.
	 *
	 * @see ClaimsParty#getAttributesSelection()
	 */
	@XmlElement(name = "AttributesSelection")
	private AttributesSelection attributesSelection;

	/**
	 * Constant attributes to be added for this RP.
	 */
	@XmlElement(name = "ConstAttributes")
	private ConstAttributes constAttributes;

	/**
	 * IDM lookup configuration for this RP.
	 */
	@XmlElement(name = "IDMLookup")
	private IdmLookup idmLookup;

	/**
	 * Properties selection identifies the computed/derived attributes passed through to the RP.
	 */
	@XmlElement(name = "PropertiesSelection")
	private AttributesSelection propertiesSelection;

	/**
	 * Profile selection configuration for this RP.
	 */
	@XmlElement(name = "ProfileSelection")
	private ProfileSelection profileSelection;

	/**
	 * Script hooks. Only scripts related to this RP are executed.
	 */
	@XmlElement(name = "Scripts")
	private Scripts scripts;

	// cached configs

	private transient List<Credential> rpTrustCredentials;

	private transient Credential rpSigner;

	private transient Credential rpEncryptionCred;

	// Lombok would generate this, but the compiler complains about not implementing RelyingPartyConfig
	@Override
	public String getId() {
		return id;
	}

	// XmlTransient not allowed on transient fields (the Javadoc does not say transient is considered XmlTransient):

	@XmlTransient
	public List<Credential> getRpTrustCredentials() {
		return rpTrustCredentials;
	}

	@XmlTransient
	public Credential getRpSigner() {
		return rpSigner;
	}

	@XmlTransient
	public Credential getEncryptionCred() {
		return rpEncryptionCred;
	}

	public void setEnabled(FeatureEnum enabled) {
		this.enabled = FeatureEnum.getName(enabled);
	}

	public FeatureEnum getEnabled() {
		return FeatureEnum.ofName(enabled);
	}

	// derived

	public boolean isSsoEnabled() {
		return sso != null && sso.isEnabled();
	}

	public Optional<String> getSloUrl(SloProtocol protocol) {
		if (sso == null) {
			return Optional.empty();
		}
		// 1. use SLO URL attribute (we might get rid of that)
		if (StringUtils.isNotEmpty(sso.getSloUrl())) {
			return Optional.of(sso.getSloUrl());
		}
		// 2. find a matching SloUrl element for RESPONSE for protocol
		return sso.getSloResponse().stream()
				.filter(slo -> slo.hasSloUrlForResponse(protocol)).map(SloResponse::getUrl)
				.findFirst();
	}

	public Optional<String> getSloIssuer(SloProtocol protocol) {
		if (sso == null) {
			return Optional.empty();
		}
		return sso.getSloResponse().stream()
				.filter(slo -> slo.hasIssuerForResponse(protocol)).map(SloResponse::getIssuer)
				.findFirst();
	}

	public boolean requireSignedAuthnRequest() {
		return PropertyUtil.evaluatePropery(securityPolicies, SecurityPolicies::getRequireSignedAuthnRequest,
				() -> true);
	}

	public boolean requireSignedLogoutRequest() {
		return PropertyUtil.evaluatePropery(securityPolicies, SecurityPolicies::getRequireSignedLogoutRequest,
				() -> true);
	}

	public boolean requireSignedResponse(boolean defaultValue) {
		return PropertyUtil.evaluatePropery(securityPolicies, SecurityPolicies::getRequireSignedResponse,
				() -> defaultValue);
	}

	public int getSsoMinQoaLevel(int defaultValue) {
		return PropertyUtil.evaluatePropery(securityPolicies, SecurityPolicies::getSsoMinQoaLevel, () -> defaultValue);
	}

	public List<OidcClient> getOidcClients() {
		return oidc != null && oidc.getClients() != null ? oidc.getClients() : Collections.emptyList();
	}

	public ProtocolEndpoints getSamlProtocolEndpoints() {
		return saml != null ? saml.getProtocolEndpoints() : null;
	}

	public ArtifactBinding getSamlArtifactBinding() {
		return saml != null ? saml.getArtifactBinding() : null;
	}

	public Encryption getEncryption() { return saml != null ? saml.getEncryption() : null; }

	public Signature getSignature() { return saml != null ? saml.getSignature() : null; }

	public Saml initializedSaml() {
		if (saml == null) {
			saml = new Saml();
		}
		return saml;
	}

	public SignatureParameters.SignatureParametersBuilder getSignatureParametersBuilder() {
		var builder = saml != null && saml.getSignature() != null ?
				saml.getSignature().getSignatureParametersBuilder() :
				SignatureParameters.builder();
		return builder
				.credential(getRpSigner());
	}

	public boolean isValidInboundBinding(SamlBinding samlBinding) {
		if (getSamlArtifactBinding() == null) {
			return true;
		}
		return getSamlArtifactBinding().validInboundBinding(samlBinding);
	}

	// disable setting OriginalIssuer on Attribute - defaults to true
	public boolean isDelegateOrigin() {
		return securityPolicies == null || securityPolicies.getDelegateOrigin() == null ||
				securityPolicies.getDelegateOrigin();
	}

	public List<Flow> getFlows() {
		return (flowPolicies != null && flowPolicies.enabled()) ?
				flowPolicies.getFlows() : Collections.emptyList();
	}

	public boolean sameHrd(RelyingParty relyingParty) {
		if (this.claimsProviderMappings == null || relyingParty.claimsProviderMappings == null) {
			return false;
		}
		return ListUtils.isEqualList(this.claimsProviderMappings.getClaimsProviderList(),
				relyingParty.claimsProviderMappings.getClaimsProviderList());
	}

	public Optional<ClaimsProviderRelyingParty> getCpMappingForAlias(String rpAliasId) {
		if (rpAliasId == null || claimsProviderMappings == null || claimsProviderMappings.getClaimsProviderList() == null) {
			return Optional.empty();
		}
		return claimsProviderMappings.getClaimsProviderList().stream()
				.filter(cpRp -> rpAliasId.equals(cpRp.getRelyingPartyAlias())).findFirst();
	}

}
