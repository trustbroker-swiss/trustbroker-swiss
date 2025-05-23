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

package swiss.trustbroker.wstrust.service;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.soap.wsfed.AppliesTo;
import org.opensaml.soap.wstrust.KeyType;
import org.opensaml.soap.wstrust.RequestSecurityToken;
import org.opensaml.soap.wstrust.RequestType;
import org.opensaml.soap.wstrust.TokenType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.api.idm.service.IdmQueryService;
import swiss.trustbroker.audit.service.AuditService;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.common.saml.util.CredentialReader;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.common.saml.util.SamlIoUtil;
import swiss.trustbroker.common.saml.util.SamlUtil;
import swiss.trustbroker.common.saml.util.SoapUtil;
import swiss.trustbroker.common.util.WSSConstants;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.SecurityChecks;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.SecurityPolicies;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.mapping.service.ClaimsMapperService;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.saml.service.RelyingPartyService;
import swiss.trustbroker.script.service.ScriptService;
import swiss.trustbroker.test.saml.util.SamlTestBase;

@SpringBootTest
@ContextConfiguration(classes = WsTrustService.class)
class WsTrustServiceTest {

	private static final String SAMPLE_RST_REQUEST_XMLSOAP_ADDRESSING = """
			<wst:RequestSecurityToken xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
			  <wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
				<wsa:EndPointReference xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">
				  <wsa:Address xmlns:wsa="http://www.w3.org/2005/08/addressing">urn:SAMPLE_RP</wsa:Address>
				</wsa:EndPointReference>
			  </wsp:AppliesTo>
			  <wst:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer</wst:KeyType>
			  <wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>
			  <wst:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0</wst:TokenType>
			</wst:RequestSecurityToken>
			""";

	private static final String SAMPLE_RST_REQUEST_W3_ADDRESSING = """
			<wst:RequestSecurityToken xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
				<wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>
				<wst:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0</wst:TokenType>
				<wst:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer</wst:KeyType>
				<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
					<wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">
						<wsa:Address>urn:SAMPLE_RP</wsa:Address>
					</wsa:EndpointReference>
				</wsp:AppliesTo>
			</wst:RequestSecurityToken>
			""";

	@Autowired
	WsTrustService wsTrustService;

	@MockitoBean
	CredentialReader credentialReader;

	@MockitoBean
	TrustBrokerProperties trustBrokerProperties;

	@MockitoBean
	RelyingPartySetupService relyingPartySetupService;

	@MockitoBean
	ScriptService scriptService;

	@MockitoBean
	IdmQueryService idmQueryService;

	@MockitoBean
	RelyingPartyService relyingPartyService;

	@MockitoBean
	AuditService auditService;

	@MockitoBean
	ClaimsMapperService claimsMapperService;

	@Test
	void smokeTest() {
		assertNotNull(wsTrustService);
	}

	@BeforeAll
	static void setup() {
		SamlInitializer.initSamlSubSystem();
	}

	@Test
	void processSecurityTokenNullTest() {
		assertThrows(RequestDeniedException.class, () -> {
			wsTrustService.processSecurityToken(null, "assertionId");
		});
	}

	@Test
	void processSecurityTokenKeyTypeNullTest() {
		RequestSecurityToken requestSecTokenType = givenRequestSecToken(null, null, null);
		assertThrows(RequestDeniedException.class, () -> {
			wsTrustService.processSecurityToken(requestSecTokenType, "assertionId");
		});
	}

	@Test
	void processSecurityTokenKeyTypeInvalidTest() {
		RequestSecurityToken requestSecTokenType = givenRequestSecToken(givenKeyType("InvalidKeyType"),
				givenTokenType("invalidType"), null);
		assertThrows(RequestDeniedException.class, () -> {
			wsTrustService.processSecurityToken(requestSecTokenType, "assertionId");
		});
	}

	@Test
	void processSecurityTokenRequestTypeNullTest() {
		RequestSecurityToken requestSecTokenType = givenRequestSecToken(givenKeyType(KeyType.BEARER),
				givenTokenType(WSSConstants.WSS_SAML2_TOKEN_TYPE), null);
		assertThrows(RequestDeniedException.class, () -> {
			wsTrustService.processSecurityToken(requestSecTokenType, "assertionId");
		});
	}

	@Test
	void processSecurityTokenRequestTypeInvalidTest() {
		RequestSecurityToken requestSecTokenType = givenRequestSecToken(givenKeyType(KeyType.BEARER),
				givenTokenType(WSSConstants.WSS_SAML2_TOKEN_TYPE), givenInvalidRequestType("InvalidRequestType"));
		assertThrows(RequestDeniedException.class, () -> {
			wsTrustService.processSecurityToken(requestSecTokenType, "assertionId");
		});
	}

	@Test
	void processSecurityTokenTokenTypeNullTest() {
		RequestSecurityToken requestSecTokenType = givenRequestSecToken(givenKeyType(KeyType.BEARER), null,
				givenInvalidRequestType(RequestType.ISSUE));
		assertThrows(RequestDeniedException.class, () -> {
			wsTrustService.processSecurityToken(requestSecTokenType, "assertionId");
		});
	}

	@Test
	void processSecurityTokenTokenTypeInvalidTest() {
		RequestSecurityToken requestSecTokenType = givenRequestSecToken(givenKeyType(KeyType.BEARER),
				givenTokenType("invalidType"), givenInvalidRequestType(RequestType.ISSUE));
		assertThrows(RequestDeniedException.class, () -> {
			wsTrustService.processSecurityToken(requestSecTokenType, "assertionId");
		});
	}


	@Test
	void processSecurityTokenValidTest() {
		RequestSecurityToken requestSecTokenType = givenRequestSecToken(givenKeyType(KeyType.BEARER),
				givenTokenType(WSSConstants.WSS_SAML2_TOKEN_TYPE), givenInvalidRequestType(RequestType.ISSUE));
		assertDoesNotThrow(() -> {
			wsTrustService.processSecurityToken(requestSecTokenType, "assertionId");
		});
	}

	@ParameterizedTest
	@MethodSource
	void unmarshallDomElement(String request) throws Exception {
		var bytes = request.getBytes(StandardCharsets.UTF_8);
		var requestSecurityTokenType = SamlIoUtil.getDomElementFromStream(new ByteArrayInputStream(bytes), "RST");
		RequestSecurityToken requestSecurityToken = SoapUtil.unmarshallDomElement(requestSecurityTokenType);
		assertThat(requestSecurityToken.getDOM(), is(not(nullValue())));
		var elements = requestSecurityToken.getUnknownXMLObjects()
				.stream()
				.map(xmlobj -> xmlobj.getElementQName().getLocalPart())
				.toList();
		assertThat(elements, containsInAnyOrder("AppliesTo", "KeyType", "RequestType", "TokenType"));
		// verify the CompatEndPointReferenceUnmarshaller workaround
		for (var childElement : requestSecurityToken.getUnknownXMLObjects()) {
			if (childElement instanceof AppliesTo appliesTo) {
				assertThat(appliesTo.getEndPointReference(), is(not(nullValue())));
				assertThat(appliesTo.getEndPointReference().getAddress(), is(not(nullValue())));
				assertThat(appliesTo.getEndPointReference().getAddress().getValue(), is("urn:SAMPLE_RP"));
			}
		}
	}

	@Test
	void createAssertionTest() {
		var cpResponse = givenCpResponseWithDuplicates();
		int initialUserDetailsSize = cpResponse.getUserDetails().size();
		var cpAttributes = givenCpAttributesWithDuplicates();
		var requestHeaderAssertion = givenRequestAssertion();
		String addressFromRequest = "addressFromRequest";
		when(relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(addressFromRequest, null))
				.thenReturn(givenRp());
		doReturn(SecurityChecks.builder()
							   .doSignAssertions(true)
							   .build()).when(trustBrokerProperties)
										.getSecurity();
		var assertion = wsTrustService.createAssertion(cpAttributes, cpResponse, "anyId",
				requestHeaderAssertion, addressFromRequest);
		var attributeStatements = assertion.getAttributeStatements();
		assertTrue(attributeStatements.get(0).getAttributes().size() < initialUserDetailsSize + cpAttributes.size());
		assertEquals(requestHeaderAssertion.getSubject().getNameID().getValue(), assertion.getSubject().getNameID().getValue());
		assertEquals(1, attributeOccurrenceInList(attributeStatements.get(0).getAttributes(),
				CoreAttributeName.CLAIMS_NAME.getName(), "claimName", "CP1"));
	}

	private static RelyingParty givenRp() {
		return RelyingParty.builder()
						   .id("rpIssuerId")
						   .rpSigner(SamlTestBase.dummyCredential())
						   .securityPolicies(
									 SecurityPolicies.builder()
													 .delegateOrigin(false)
													 .build()
							 ).build();
	}

	private Assertion givenRequestAssertion() {
		var assertion = OpenSamlUtil.buildAssertionObject();
		assertion.setIssueInstant(Instant.now());
		assertion.setID(UUID.randomUUID().toString());
		assertion.setIssuer(OpenSamlUtil.buildSamlObject(Issuer.class));
		assertion.getIssuer().setValue("TEST_AUDIENCE");
		var nameId = SamlFactory.createNameId("name1@localhost", NameIDType.EMAIL, null);
		assertion.setSubject(SamlFactory.createSubject(nameId, "RELAY_STATE", "rpIssuerId", 100));
		return assertion;

	}

	private List<Attribute> givenCpAttributesWithDuplicates() {
		List<Attribute> attributes = new ArrayList<>();
		attributes.add(SamlFactory.createAttribute(CoreAttributeName.CLAIMS_NAME.getName(), "claimName", "CP1"));
		attributes.add(SamlFactory.createAttribute(CoreAttributeName.CLAIMS_NAME.getName(), "claimName", "CP1"));
		attributes.add(SamlFactory.createAttribute(CoreAttributeName.NAME_ID.getName(), "nameId",
				CoreAttributeName.NAME_ID.getNamespaceUri()));

		return attributes;
	}

	private int attributeOccurrenceInList(List<Attribute> attributes, String name, String value, String originalIssuer) {
		int count = 0;
		for (Attribute attribute : attributes) {
			if (attribute.getName().equals(name) && SamlUtil.getAttributeValues(attribute).get(0).equals(value) &&
					originalIssuer.equals(SamlUtil.getOriginalIssuerFromAttribute(attribute))) {
				count++;
			}
		}
		return count;
	}

	private CpResponse givenCpResponseWithDuplicates() {
		Map<Definition, List<String>> queryResponse = new HashMap<>();
		queryResponse.put(new Definition(CoreAttributeName.HOME_REALM), List.of("trustbroker:test:test"));
		queryResponse.put(new Definition(CoreAttributeName.EMAIL), List.of("idp-mock"));
		queryResponse.put(Definition.builder()
									.namespaceUri(CoreAttributeName.EMAIL.getNamespaceUri())
									.build(),
				List.of("idp-mock"));
		queryResponse.put(new Definition(CoreAttributeName.ISSUED_CLIENT_EXT_ID), List.of("TEST"));

		var cpResponse = new CpResponse();
		cpResponse.setRpIssuer("urn:ANY");
		cpResponse.setNameId("nameId");
		cpResponse.setIssuer("issuer");
		cpResponse.setHomeName("homeName");
		cpResponse.setClientExtId("clientExtId");
		cpResponse.setAttribute(CoreAttributeName.HOME_NAME.getNamespaceUri(), "testhomename");
		cpResponse.setUserDetails(queryResponse);

		return cpResponse;

	}

	static Object[][] unmarshallDomElement() {
		return new Object[][] {
				{ SAMPLE_RST_REQUEST_W3_ADDRESSING },
				{ SAMPLE_RST_REQUEST_XMLSOAP_ADDRESSING }
		};
	}

	private KeyType givenKeyType(String keyTypeValue) {
		KeyType keyType = (KeyType) XMLObjectSupport.buildXMLObject(KeyType.ELEMENT_NAME);
		keyType.setURI(keyTypeValue);
		return keyType;
	}

	private RequestType givenInvalidRequestType(String requestValue) {
		RequestType requestType = (RequestType) XMLObjectSupport.buildXMLObject(RequestType.ELEMENT_NAME);
		requestType.setURI(requestValue);

		return requestType;
	}

	private TokenType givenTokenType(String tokenTypeValue) {
		TokenType tokenType = (TokenType) XMLObjectSupport.buildXMLObject(TokenType.ELEMENT_NAME);
		tokenType.setURI(tokenTypeValue);
		return tokenType;
	}

	private RequestSecurityToken givenRequestSecToken(KeyType keyType, TokenType tokenType, RequestType requestType) {
		RequestSecurityToken requestSecurityToken =
				(RequestSecurityToken) XMLObjectSupport.buildXMLObject(RequestSecurityToken.ELEMENT_NAME);

		if (keyType != null) {
			requestSecurityToken.getUnknownXMLObjects().add(keyType);
		}

		if (tokenType != null) {
			requestSecurityToken.getUnknownXMLObjects().add(tokenType);
		}

		if (requestType != null) {
			requestSecurityToken.getUnknownXMLObjects().add(requestType);
		}

		return requestSecurityToken;
	}

}
