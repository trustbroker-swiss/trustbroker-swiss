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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.security.credential.Credential;
import swiss.trustbroker.common.config.KeystoreProperties;
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.common.saml.util.SamlIoUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.ArtifactResolution;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.config.dto.SamlProperties;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderSetup;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.RelyingPartySetup;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.test.saml.util.SamlTestBase;
import swiss.trustbroker.util.ApiSupport;

class FederationMetadataServiceTest {

	private static final String CONSUMER_URL = "https://localhost/acs";

	private static final String PERIMETER_URL = "https://localhost/perimeter";

	private static final String ARP_URL = "https://localhost/arp";

	private static final int ARP_INDEX = 1;

	private FederationMetadataService federationMetadataService;

	@BeforeAll
	static void init() {
		SamlInitializer.initSamlSubSystem();
	}

	@BeforeEach
	void setUp() {
		var trustBrokerProperties = givenProperties();
		var relyingPartySetupService = givenRpSetupService(trustBrokerProperties);
		federationMetadataService = new FederationMetadataService(trustBrokerProperties, relyingPartySetupService);
	}

	private RelyingPartySetupService givenRpSetupService(TrustBrokerProperties trustBrokerProperties) {
		var relyingPartiesMapping = new RelyingPartyDefinitions();

		List<Credential> cpEncryptionTrustCred = new ArrayList<>();
		cpEncryptionTrustCred.add(SamlTestBase.dummyCredential());

		var claimsParty = ClaimsParty.builder()
				.cpEncryptionTrustCredentials(cpEncryptionTrustCred)
				.build();

		List<ClaimsParty> claimParties = new ArrayList<>();
		claimParties.add(claimsParty);

		var claimsProviderSetup = ClaimsProviderSetup.builder()
				.claimsParties(claimParties)
				.build();

		relyingPartiesMapping.setClaimsProviderSetup(claimsProviderSetup);

		List<RelyingParty> relyingParties = new ArrayList<>();
		var relyingParty = RelyingParty.builder()
				.rpEncryptionCred(SamlTestBase.dummyCredential())
				.build();
		relyingParties.add(relyingParty);

		var relyingPartySetup = RelyingPartySetup.builder()
				.relyingParties(relyingParties)
				.build();
		relyingPartiesMapping.setRelyingPartySetup(relyingPartySetup);
		return new RelyingPartySetupService(relyingPartiesMapping, trustBrokerProperties, Collections.emptyList());
	}

	private static TrustBrokerProperties givenProperties() {
		var trustBrokerProperties = new TrustBrokerProperties();
		var signer = new KeystoreProperties();
		trustBrokerProperties.setSigner(signer);
		trustBrokerProperties.setRolloverSigner(signer);
		signer.setSignerCert(SamlTestBase.filePathFromClassPath(SamlTestBase.X509_RSAENC_JKS));
		signer.setPassword(SamlTestBase.X509_RSAENC_PW);
		signer.setKeyEntryId(SamlTestBase.X509_RSAENC_ALIAS);
		trustBrokerProperties.setRolloverSigner(signer);
		var ar = new ArtifactResolution();
		ar.setServiceUrl(ARP_URL);
		ar.setIndex(ARP_INDEX);
		var saml = new SamlProperties();
		saml.setConsumerUrl(CONSUMER_URL);
		saml.setArtifactResolution(ar);
		trustBrokerProperties.setSaml(saml);
		trustBrokerProperties.setPerimeterUrl(PERIMETER_URL);
		return trustBrokerProperties;
	}

	@Test
	void getFederationMetadata() throws MessageEncodingException {
		var result = federationMetadataService.getFederationMetadata();
		assertThat(result, is(not(nullValue())));
		var samlObj = SamlIoUtil.getXmlObjectFromStream(
				new ByteArrayInputStream(result.getBytes(StandardCharsets.UTF_8)), "test");
		assertThat(samlObj, is(instanceOf(EntityDescriptor.class)));
		var entityDescriptor = (EntityDescriptor) samlObj;
		assertThat(entityDescriptor.isSigned(), is(true));
		validateIdp(entityDescriptor);
		validateSp(entityDescriptor);
		// AuthnAuthority
		var authDescriptor = entityDescriptor.getAuthnAuthorityDescriptor(FederationMetadataService.SUPPORTED_PROTOCOL);
		assertThat(authDescriptor, is(not(nullValue())));
		var authServices = authDescriptor.getAuthnQueryServices();
		validateLocation(authServices, PERIMETER_URL + ApiSupport.ADFS_SERVICES_PATH);
		validateBinding(authServices, SAMLConstants.SAML2_SOAP11_BINDING_URI);
	}

	private void validateIdp(EntityDescriptor entityDescriptor) {
		var idpSsoDescriptor = entityDescriptor.getIDPSSODescriptor(FederationMetadataService.SUPPORTED_PROTOCOL);
		assertThat(idpSsoDescriptor, is(not(nullValue())));
		assertThat(idpSsoDescriptor.getWantAuthnRequestsSigned(), is(true));
		assertThat(idpSsoDescriptor.getSupportedProtocols(), contains(FederationMetadataService.SUPPORTED_PROTOCOL));
		validateNameIdFormats(idpSsoDescriptor.getNameIDFormats());
		// SSO
		var ssoServices = idpSsoDescriptor.getSingleSignOnServices();
		validateLocation(ssoServices, CONSUMER_URL);
		validateBindings(ssoServices);
		// SLO
		var sloServices = idpSsoDescriptor.getSingleLogoutServices();
		validateLocation(sloServices, CONSUMER_URL);
		validateBindings(sloServices);
		// ARP
		var arpServices = idpSsoDescriptor.getArtifactResolutionServices();
		validateLocation(arpServices, ARP_URL);
		validateArpIndexes(arpServices, ARP_INDEX);
		validateBinding(arpServices, SAMLConstants.SAML2_SOAP11_BINDING_URI);
		// KeyDescriptor
		validateKeyDescriptor(idpSsoDescriptor.getKeyDescriptors());
	}

	private void validateSp(EntityDescriptor entityDescriptor) {
		var spSsoDescriptor = entityDescriptor.getSPSSODescriptor(FederationMetadataService.SUPPORTED_PROTOCOL);
		assertThat(spSsoDescriptor, is(not(nullValue())));
		assertThat(spSsoDescriptor.getWantAssertionsSigned(), is(true));
		assertThat(spSsoDescriptor.isAuthnRequestsSigned(), is(true));
		assertThat(spSsoDescriptor.getSupportedProtocols(), contains(FederationMetadataService.SUPPORTED_PROTOCOL));
		validateNameIdFormats(spSsoDescriptor.getNameIDFormats());
		// ACS
		var acsServices = spSsoDescriptor.getAssertionConsumerServices();
		validateLocation(acsServices, CONSUMER_URL);
		validateBindings(acsServices);
		// SLO
		var spSloServices = spSsoDescriptor.getSingleLogoutServices();
		validateLocation(spSloServices, CONSUMER_URL);
		validateBindings(spSloServices);
		// KeyDescriptors
		validateKeyDescriptor(spSsoDescriptor.getKeyDescriptors());
	}

	private static void validateNameIdFormats(List<NameIDFormat> nameIDFormats) {
		assertThat(nameIDFormats.stream().map(NameIDFormat::getURI).toList(),
				is(FederationMetadataService.SUPPORTED_NAMEID_FORMATS));
	}

	private static void validateBindings(List<? extends Endpoint> services) {
		for (String binding : FederationMetadataService.SUPPORTED_SAML_BINDINGS) {
			validateBinding(services, binding);
		}
	}

	private static void validateBinding(List<? extends Endpoint> services, String binding) {
		assertThat(services.stream().anyMatch(svc -> binding.equals(svc.getBinding())), is(true));
	}

	private static void validateLocation(List<? extends Endpoint> services, String location) {
		for (var service : services) {
			assertThat(service.getLocation(), is(location));
		}
	}

	private static void validateArpIndexes(List<? extends ArtifactResolutionService> services, int index) {
		for (var service : services) {
			assertThat(service.getIndex(), is(index));
		}
	}

	private static void validateKeyDescriptor(List<KeyDescriptor> keyDescriptors) {
		assertThat(keyDescriptors, hasSize(3));
		for (var keyDescriptor : keyDescriptors) {
			assertThat(keyDescriptor.getKeyInfo(), is(not(nullValue())));
			assertThat(keyDescriptor.getUse(), is(not(nullValue())));
		}
	}

}
