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

package swiss.trustbroker.federation.service;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.xml.SerializeSupport;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.AuthnAuthorityDescriptor;
import org.opensaml.saml.saml2.metadata.AuthnQueryService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.springframework.stereotype.Service;
import org.w3c.dom.Element;
import swiss.trustbroker.common.config.KeystoreProperties;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.CredentialReader;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.saml.util.SamlUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.util.ApiSupport;

@Service
@Slf4j
public class FederationMetadataService {

	static final List<String> SUPPORTED_SAML_BINDINGS = List.of(
			SAMLConstants.SAML2_POST_BINDING_URI,
			SAMLConstants.SAML2_REDIRECT_BINDING_URI,
			SAMLConstants.SAML2_ARTIFACT_BINDING_URI);

	static final List<String> SUPPORTED_NAMEID_FORMATS = List.of(NameIDType.PERSISTENT, NameIDType.TRANSIENT);

	static final String SUPPORTED_PROTOCOL = SAMLConstants.SAML20P_NS;

	private final TrustBrokerProperties trustBrokerProperties;

	private final Credential signer;

	private final List<Credential> allSigners;

	private final List<Credential> cpEncryptionCreds;

	private final List<Credential> rpEncryptionCreds;

	FederationMetadataService(TrustBrokerProperties trustBrokerProperties, RelyingPartySetupService relyingPartySetupService) {
		this.trustBrokerProperties = trustBrokerProperties;

		// signer
		signer = CredentialReader.createCredential(trustBrokerProperties.getSigner()); // sign
		allSigners = loadTrustableCerts(trustBrokerProperties.getRolloverSigner()); // trust
		cpEncryptionCreds = relyingPartySetupService.getCpsEncryptionTrustCredentials(); // cp credentials
		rpEncryptionCreds = relyingPartySetupService.getRpsEncryptionCredentials(); // rp credentials
	}

	private List<Credential> loadTrustableCerts(KeystoreProperties keystoreProperties) {
		var ret = new ArrayList<Credential>();
		ret.add(signer);
		// Support any number of rollover certs, our peers might be challenged though
		try {
			var file = new File(keystoreProperties.getSignerCert());
			if (file.exists()) {
				ret.addAll(CredentialReader.readTrustCredentials(
						keystoreProperties.getSignerCert(),
						keystoreProperties.getType(),
						keystoreProperties.getPassword(),
						keystoreProperties.getKeyEntryId()
				));
			}
			log.info("Loaded metaDataSignerTrust={} trustCount={}", keystoreProperties.getSignerCert(), ret.size());
		}
		catch (TechnicalException ex) {
			log.error("Rollover signer certificate loading from file={} failed with message={}",
					trustBrokerProperties.getRolloverSigner(), ex.getInternalMessage(), ex);
		}
		return ret;
	}

	public String getFederationMetadata() {
		try {
			EntityDescriptor entityDescriptor = generateMetadata();
			Element domDescriptor = SamlUtil.marshallMessage(entityDescriptor);
			SamlUtil.removeNewLinesFromCertificates(domDescriptor);
			return SerializeSupport.prettyPrintXML(domDescriptor);
		}
		catch (MessageEncodingException e) {
			throw new TechnicalException(String.format("Could not encode federation metadata ex=%s", e.getMessage()));
		}
	}

	public EntityDescriptor generateMetadata() {
		EntityDescriptor descriptor = OpenSamlUtil.buildSamlObject(EntityDescriptor.class);
		UUID uuid = UUID.randomUUID();
		descriptor.setID("_" + uuid);
		descriptor.setEntityID(trustBrokerProperties.getIssuer());

		IDPSSODescriptor ssoDescriptor = buildIdpSsoDescriptor();
		if (ssoDescriptor != null) {
			descriptor.getRoleDescriptors().add(ssoDescriptor);
		}

		SPSSODescriptor spssoDescriptor = buildSpSsoDescriptor();
		if (spssoDescriptor != null) {
			descriptor.getRoleDescriptors().add(spssoDescriptor);
		}

		var authnAuthorityDescriptor = buildAuthnAuthorityDescriptor();
		descriptor.getRoleDescriptors().add(authnAuthorityDescriptor);

		// NOTE: Currently all signers use the same cert so the following is not really an issue but with multiple signers
		// We use sha256 default signing here to not worsen the problem by just picking an RYP setup for key material and config
		Signature signature = SamlFactory.prepareSignableObject(
				descriptor, signer, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, null, null);
		SamlUtil.signSamlObject(descriptor, signature);
		return descriptor;
	}

	protected IDPSSODescriptor buildIdpSsoDescriptor() {
		var consumerUrl = trustBrokerProperties.getSamlConsumerUrl();
		var idpDescriptor = OpenSamlUtil.buildSamlObject(IDPSSODescriptor.class);
		idpDescriptor.setWantAuthnRequestsSigned(true);
		idpDescriptor.addSupportedProtocol(SUPPORTED_PROTOCOL);
		for (String binding : SUPPORTED_SAML_BINDINGS) {
			idpDescriptor.getSingleLogoutServices().add(getSingleLogoutService(consumerUrl, binding));
			idpDescriptor.getSingleSignOnServices().add(getSingleSignOnService(consumerUrl, binding));
		}
		idpDescriptor.getArtifactResolutionServices().add(getArtifactResolutionService());
		for (String nameIdFormat : SUPPORTED_NAMEID_FORMATS) {
			idpDescriptor.getNameIDFormats().add(getNameIdFormat(nameIdFormat));
		}
		allSigners.forEach(cred -> idpDescriptor.getKeyDescriptors().add(getKeyDescriptor(cred, UsageType.SIGNING)));
		if (!cpEncryptionCreds.isEmpty()) {
			cpEncryptionCreds.forEach(cred -> idpDescriptor.getKeyDescriptors().add(getKeyDescriptor(cred, UsageType.ENCRYPTION)));
		}
		return idpDescriptor;
	}

	private ArtifactResolutionService getArtifactResolutionService() {
		var artifactResolutionService = OpenSamlUtil.buildSamlObject(ArtifactResolutionService.class);
		artifactResolutionService.setBinding(SAMLConstants.SAML2_SOAP11_BINDING_URI);
		artifactResolutionService.setLocation(trustBrokerProperties.getSaml().getArtifactResolution().getServiceUrl());
		artifactResolutionService.setIndex(trustBrokerProperties.getSaml().getArtifactResolution().getIndex());
		return artifactResolutionService;
	}

	private static NameIDFormat getNameIdFormat(String nameIdFormat) {
		NameIDFormat nameIDFormat = OpenSamlUtil.buildSamlObject(NameIDFormat.class);
		nameIDFormat.setURI(nameIdFormat);
		return nameIDFormat;
	}

	protected SPSSODescriptor buildSpSsoDescriptor() {
		var consumerURL = trustBrokerProperties.getSamlConsumerUrl();
		var spssoDescriptor = OpenSamlUtil.buildSamlObject(SPSSODescriptor.class);
		spssoDescriptor.setAuthnRequestsSigned(true);
		spssoDescriptor.setWantAssertionsSigned(true);
		spssoDescriptor.addSupportedProtocol(SUPPORTED_PROTOCOL);
		for (String binding : SUPPORTED_SAML_BINDINGS) {
			spssoDescriptor.getSingleLogoutServices().add(getSingleLogoutService(consumerURL, binding));
			var index = spssoDescriptor.getAssertionConsumerServices().size();
			spssoDescriptor.getAssertionConsumerServices().add(getAssertionConsumerService(consumerURL, binding, index));
		}
		spssoDescriptor.getArtifactResolutionServices().add(getArtifactResolutionService());
		for (String nameIdFormat : SUPPORTED_NAMEID_FORMATS) {
			spssoDescriptor.getNameIDFormats().add(getNameIdFormat(nameIdFormat));
		}
		allSigners.forEach(cred -> spssoDescriptor.getKeyDescriptors().add(getKeyDescriptor(cred, UsageType.SIGNING)));
		if (!rpEncryptionCreds.isEmpty()) {
			rpEncryptionCreds.forEach(cred -> spssoDescriptor.getKeyDescriptors().add(getKeyDescriptor(cred, UsageType.ENCRYPTION)));
		}
		return spssoDescriptor;
	}

	private static KeyDescriptor getKeyDescriptor(Credential credential, UsageType usageType) {
		KeyDescriptor keyDescriptor = OpenSamlUtil.buildSamlObject(KeyDescriptor.class);
		KeyInfo keyInfo = SamlFactory.createKeyInfo(credential);
		keyDescriptor.setUse(usageType);
		keyDescriptor.setKeyInfo(keyInfo);
		return keyDescriptor;
	}

	private static SingleSignOnService getSingleSignOnService(String location, String binding) {
		SingleSignOnService sso = OpenSamlUtil.buildSamlObject(SingleSignOnService.class);
		sso.setLocation(location);
		sso.setBinding(binding);
		return sso;
	}

	private static SingleLogoutService getSingleLogoutService(String location, String binding) {
		SingleLogoutService sso = OpenSamlUtil.buildSamlObject(SingleLogoutService.class);
		sso.setLocation(location);
		sso.setBinding(binding);
		return sso;
	}

	private static AssertionConsumerService getAssertionConsumerService(String location, String binding, int index) {
		AssertionConsumerService assertionConsumerService = OpenSamlUtil.buildSamlObject(AssertionConsumerService.class);
		assertionConsumerService.setLocation(location);
		assertionConsumerService.setBinding(binding);
		assertionConsumerService.setIndex(index);
		return assertionConsumerService;
	}

	private AuthnAuthorityDescriptor buildAuthnAuthorityDescriptor() {
		AuthnAuthorityDescriptor authnAuthorityDescriptor = OpenSamlUtil.buildSamlObject(AuthnAuthorityDescriptor.class);
		authnAuthorityDescriptor.addSupportedProtocol(SUPPORTED_PROTOCOL);
		authnAuthorityDescriptor.getAuthnQueryServices().add(getAuthnQueryService());
		return authnAuthorityDescriptor;
	}

	private AuthnQueryService getAuthnQueryService() {
		AuthnQueryService authnQueryService = OpenSamlUtil.buildSamlObject(AuthnQueryService.class);
		authnQueryService.setBinding(SAMLConstants.SAML2_SOAP11_BINDING_URI);
		String perimeterUrl = trustBrokerProperties.getPerimeterUrl();
		authnQueryService.setLocation(perimeterUrl + ApiSupport.ADFS_SERVICES_PATH);
		return authnQueryService;
	}

}
