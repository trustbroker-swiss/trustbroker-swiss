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

package swiss.trustbroker.saml.service;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import swiss.trustbroker.api.announcements.service.AnnouncementService;
import swiss.trustbroker.audit.service.AuditService;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.saml.dto.SignatureContext;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlContextClass;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.NetworkConfig;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.config.dto.SamlNamespace;
import swiss.trustbroker.config.dto.SamlProperties;
import swiss.trustbroker.config.dto.SecurityChecks;
import swiss.trustbroker.federation.xmlconfig.AcWhitelist;
import swiss.trustbroker.federation.xmlconfig.ArtifactBinding;
import swiss.trustbroker.federation.xmlconfig.ArtifactBindingMode;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderRelyingParty;
import swiss.trustbroker.federation.xmlconfig.Flow;
import swiss.trustbroker.federation.xmlconfig.FlowPolicies;
import swiss.trustbroker.federation.xmlconfig.Qoa;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.RelyingPartySetup;
import swiss.trustbroker.federation.xmlconfig.Saml;
import swiss.trustbroker.homerealmdiscovery.service.NoOpHrdService;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.saml.dto.ResponseData;
import swiss.trustbroker.saml.test.util.ServiceSamlTestUtil;
import swiss.trustbroker.script.service.ScriptService;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.sessioncache.service.StateCacheService;
import swiss.trustbroker.sso.service.SsoService;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.HrdSupport;

@SpringBootTest
@ContextConfiguration(classes = { AssertionConsumerService.class, ApiSupport.class })
@TestPropertySource(properties="trustbroker.config.devmode.enabled=false")
class AssertionConsumerServiceTest {

	private static final String TEST_RP = "urn:test:MOCKRP";

	private static final String TEST_RP_ALIAS = "urn:test:MOCKRP-DIRECT";

	private static final String TEST_CP = "cpId";

	private static final String TEST_CP_MOCK = "urn:test:MOCK";

	private static final String TEST_CP_ID = "urn:test:TESTCP";

	private static final String REFERRER = "https://localhost";

	private static final String RELAY_STATE = "relay";

	@Autowired
	private AssertionConsumerService assertionConsumerService;

	@MockBean
	private TrustBrokerProperties trustBrokerProperties;

	@MockBean
	private RelyingPartyDefinitions relyingPartyDefinitions;

	@MockBean
	private RelyingPartySetupService relyingPartySetupService;

	@MockBean
	private ScriptService scriptService;

	@MockBean
	@Qualifier("stateCache")
	private StateCacheService cacheService;

	@MockBean
	private SsoService ssoService;

	@MockBean
	private AuditService auditService;

	@MockBean
	private AnnouncementService announcementService;

	@SpyBean
	private NoOpHrdService hrdService;

	@BeforeAll
	static void setup() {
		SamlInitializer.initSamlSubSystem();
	}

	@BeforeEach
	void setupTest() {
		var network = new NetworkConfig();
		doReturn(network).when(trustBrokerProperties).getNetwork();
	}

	@Test
	void testRelyingPartyToMultipleCpsFromSetup() {
		var network = trustBrokerProperties.getNetwork().getIntranetNetworkName();
		mockRequestConfiguration(TEST_RP);
		var request = new MockHttpServletRequest();
		request.addHeader(trustBrokerProperties.getNetwork().getNetworkHeader(), network);
		var rpRequest = assertionConsumerService.getRpRequestDetails(TEST_RP, "REF", "APPL", request, "TEST", null);
		assertThat(rpRequest.getClaimsProviders().stream().map(ClaimsProviderRelyingParty::getId).toList(),
				containsInAnyOrder(TEST_CP_MOCK, TEST_CP_ID));
		assertEquals("REF", rpRequest.getReferer());
		assertEquals("TEST", rpRequest.getRequestId());
		assertEquals(TEST_RP, rpRequest.getRpIssuer());
		assertTrue(rpRequest.getClaimsProviders().stream().noneMatch(cp ->
				cp.isMatchingRelyingPartyAlias(TEST_RP_ALIAS)));
		assertTrue(rpRequest.getClaimsProviders().stream().allMatch(cp ->
				cp.isValidForNetwork(network))); // valid for both networks
		assertEquals(List.of(TEST_CP_ID), rpRequest.getClaimsProviders().stream().filter(cp ->
				cp.isValidForNetwork(trustBrokerProperties.getNetwork().getInternetNetworkName()))
																		.map(ClaimsProviderRelyingParty::getId).toList());
	}

	@Test
	void testRelyingPartyToInternetOnly() {
		var network = trustBrokerProperties.getNetwork().getInternetNetworkName();
		mockRequestConfiguration(TEST_RP);
		var request = new MockHttpServletRequest();
		request.addHeader(trustBrokerProperties.getNetwork().getNetworkHeader(), network);
		var rpRequest = assertionConsumerService.getRpRequestDetails(TEST_RP,"REF", "APPL", request, "TEST", null);
		assertEquals(List.of(TEST_CP_ID), rpRequest.getClaimsProviders().stream().map(ClaimsProviderRelyingParty::getId).toList());
		assertTrue(rpRequest.getClaimsProviders().stream().allMatch(cp -> cp.isValidForNetwork(network)));
		assertTrue(rpRequest.getClaimsProviders().stream().allMatch(cp ->
				cp.isValidForNetwork(trustBrokerProperties.getNetwork().getIntranetNetworkName()))); // valid for both networks
	}

	@Test
	void testRelyingPartyAliasToDirectCpMapping() {
		mockRequestConfiguration(TEST_RP_ALIAS);
		var request = new MockHttpServletRequest();
		var rpRequest = assertionConsumerService.getRpRequestDetails(TEST_RP_ALIAS, "REF", null, request, "TEST", null);
		assertEquals(List.of("urn:test:URLTESTER"), rpRequest.getClaimsProviders().stream().map(ClaimsProviderRelyingParty::getId).toList());
		assertEquals("REF", rpRequest.getReferer());
		assertEquals("TEST", rpRequest.getRequestId());
		assertEquals(TEST_RP_ALIAS, rpRequest.getRpIssuer());
	}

	@Test
	void testRelyingPartyToSelectedCpByUrlTester() {
		mockRequestConfiguration(TEST_RP);
		var request = new MockHttpServletRequest();
		request.setCookies(new Cookie(HrdSupport.HTTP_URLTESTER_CP, TEST_CP_MOCK));
		var rpRequest = assertionConsumerService.getRpRequestDetails(TEST_RP,"REF", null, request, "TEST", null);
		assertEquals(List.of(TEST_CP_MOCK), rpRequest.getClaimsProviders().stream().map(ClaimsProviderRelyingParty::getId).toList());
	}

	@Test
	void handleSuccessCpResponseMissingResponse() {
		ResponseData<Response> responseData = ResponseData.of(null, RELAY_STATE, null);
		var ex = assertThrows(RequestDeniedException.class,
				() -> assertionConsumerService.handleSuccessCpResponse(responseData));
		assertThat(ex.getInternalMessage(), containsString("Response context is missing"));
	}

	@Test
	void handleSuccessCpResponseMissingAssertion() {
		var response = OpenSamlUtil.buildSamlObject(Response.class);
		var responseData = ResponseData.of(response, RELAY_STATE, null);
		var ex = assertThrows(RequestDeniedException.class,
				() -> assertionConsumerService.handleSuccessCpResponse(responseData));
		assertThat(ex.getInternalMessage(), containsString("No assertion"));
	}

	@Test
	void handleSuccessCpResponseMissingRelayState() {
		var response = SamlFactory.createResponse(Response.class, "myIssuer");
		response.getAssertions().add(OpenSamlUtil.buildAssertionObject());
		var responseData = ResponseData.of(response, null, null);
		var ex = assertThrows(RequestDeniedException.class,
				() -> assertionConsumerService.handleSuccessCpResponse(responseData));
		assertThat(ex.getInternalMessage(), containsString("Relay state"));
	}

	@Test
	void handleSuccessCpResponseWrongBinding() {
		var response = SamlFactory.createResponse(Response.class, TEST_CP);
		response.getAssertions().add(OpenSamlUtil.buildAssertionObject());
		mockCp(TEST_CP, ArtifactBindingMode.NOT_SUPPORTED);
		mockState(RELAY_STATE);
		var responseData = ResponseData.of(response, RELAY_STATE, SignatureContext.forArtifactBinding());
		var ex = assertThrows(RequestDeniedException.class,
				() -> assertionConsumerService.handleSuccessCpResponse(responseData));
		assertThat(ex.getInternalMessage(), containsString("does not support inbound binding"));
	}

	@Test
	void handleSuccessCpResponseAuthnRequestIssuerId() {
		var response = SamlFactory.createResponse(Response.class, TEST_CP);
		response.setStatus(SamlFactory.createResponseStatus(StatusCode.SUCCESS));
		response.setInResponseTo(RELAY_STATE);
		var rpIssuerId = "customIssuer1";
		var assertion = givenAssertion(rpIssuerId);
		response.getAssertions().add(assertion);
		var cp = mockCp(TEST_CP, ArtifactBindingMode.SUPPORTED);
		cp.setAuthnRequestIssuerId(rpIssuerId);
		var state = mockState(RELAY_STATE);
		state.setIssuer(TEST_CP);
		mockSecurityChecks(false, false, false, true);
		var responseData = ResponseData.of(response, RELAY_STATE, SignatureContext.forArtifactBinding());
		assertDoesNotThrow(() -> assertionConsumerService.handleSuccessCpResponse(responseData));
	}

	private static Assertion givenAssertion(String rpIssuerId) {
		var assertion = OpenSamlUtil.buildAssertionObject();
		assertion.setID("a123");
		assertion.setIssueInstant(Instant.now());
		assertion.setIssuer(SamlFactory.createIssuer(TEST_CP));
		var nameId = SamlFactory.createNameId("subject", NameID.X509_SUBJECT, null);
		assertion.setSubject(SamlFactory.createSubject(nameId, RELAY_STATE, rpIssuerId, 100));
		var conditions = SamlFactory.createConditions(rpIssuerId, 100);
		assertion.setConditions(conditions);
		return assertion;
	}

	@Test
	void handleFailedsCpResponseMissingResponse() {
		ResponseData<Response> responseData = ResponseData.of(null, RELAY_STATE, null);
		var ex = assertThrows(RequestDeniedException.class,
				() -> assertionConsumerService.handleFailedCpResponse(responseData));
		assertThat(ex.getInternalMessage(), containsString("Response context is missing"));
	}

	@Test
	void handleFailedCpResponseMissingRelayState() {
		var response = SamlFactory.createResponse(Response.class, "myIssuer");
		response.getAssertions().add(OpenSamlUtil.buildAssertionObject());
		// empty is not ok either
		var responseData = ResponseData.of(response, "", null);
		var ex = assertThrows(RequestDeniedException.class,
				() -> assertionConsumerService.handleFailedCpResponse(responseData));
		assertThat(ex.getInternalMessage(), containsString("Relay state"));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"true,true,true,false,true,false",
			"true,true,false,false,true,false",
			"true,false,false,true,true,false",
			"true,false,false,false,false,true",
			"false,false,false,false,false,true",
	})
	void handleFailedCpResponseFlowPolicies(boolean flowPolicies, boolean supportInfo, boolean reLogin, boolean appContinue,
			boolean aborted, boolean invalidate) {
		// cp
		mockCp(TEST_CP, null);
		// response
		var response = SamlFactory.createResponse(Response.class, TEST_CP);
		response.getAssertions().add(OpenSamlUtil.buildAssertionObject());
		response.setInResponseTo("authnRequestId");
		var status = SamlFactory.createResponseStatus(StatusCode.RESPONDER, "message", StatusCode.UNKNOWN_PRINCIPAL);
		response.setStatus(status);
		// state
		var state = mockState(RELAY_STATE);
		state.getSpStateData().setIssuer(TEST_RP);
		state.getSpStateData().setReferer(REFERRER);
		// properties
		var saml = new SamlProperties();
		saml.setFlowPolicyNamespaces(List.of(new SamlNamespace("urn:oasis:names:tc:SAML:2.0:status", null)));
		doReturn(saml).when(trustBrokerProperties).getSaml();
		mockSecurityChecks(false, true, false, false);
		doReturn(true).when(trustBrokerProperties).isHandleResponderErrors();
		// rp
		FlowPolicies policies = null;
		if (flowPolicies) {
			var flow = Flow.builder()
					.id("UnknownPrincipal")
					.supportInfo(supportInfo)
					.reLogin(reLogin)
					.appContinue(appContinue)
					.build();
			policies = FlowPolicies.builder().flows(List.of(flow)).build();
		}
		var rp = RelyingParty.builder().id(TEST_RP).flowPolicies(policies).build();
		doReturn(rp).when(relyingPartySetupService).getRelyingPartyByIssuerIdOrReferrer(TEST_RP, REFERRER);

		var responseData = ResponseData.of(response, RELAY_STATE, null);
		var result = assertionConsumerService.handleFailedCpResponse(responseData);

		assertThat(result.isAborted(), is(aborted));
		if (aborted) {
			assertThat(result.getStatusCode(), is(StatusCode.RESPONDER));
			assertThat(result.nestedStatusCode(saml), is(StatusCode.UNKNOWN_PRINCIPAL));
			assertThat(result.statusMessage(saml), is(StatusCode.UNKNOWN_PRINCIPAL));
		}
		verify(cacheService, times(invalidate ? 1 : 0)).invalidate(state, AssertionConsumerService.class.getSimpleName());
	}

	@ParameterizedTest
	@MethodSource
	void handleFailedCpResponseWrongBinding(ArtifactBindingMode mode, SignatureContext signatureContext) {
		var response = SamlFactory.createResponse(Response.class, TEST_CP);
		response.getAssertions().add(OpenSamlUtil.buildAssertionObject());
		mockCp(TEST_CP, mode);
		mockState(RELAY_STATE);
		var responseData = ResponseData.of(response, RELAY_STATE, signatureContext);
		var ex = assertThrows(RequestDeniedException.class,
				() -> assertionConsumerService.handleFailedCpResponse(responseData));
		assertThat(ex.getInternalMessage(), containsString("does not support inbound binding"));
	}

	static Object[][] handleFailedCpResponseWrongBinding() {
		return new Object[][] {
				{ ArtifactBindingMode.NOT_SUPPORTED, SignatureContext.forArtifactBinding() },
				{ ArtifactBindingMode.REQUIRED, SignatureContext.forPostBinding() },
				{ ArtifactBindingMode.REQUIRED, SignatureContext.forRedirectBinding("") }
		};
	}

	@Test
	void testGetAssertionConsumerServiceUrl() {
		doReturn(new SecurityChecks()).when(trustBrokerProperties).getSecurity();
		var url1 = "https://server1/acsurl1";
		var url2 = "https://server2/acsurl1";
		var url3 = "https://server1/slourl1";
		var url2other = "https://server2/other";
		var url2host = "https://server2/";
		var url2port = "https://server2:443/";
		var relyingParty = RelyingParty.builder()
				.id("TEST-ID")
				.acWhitelist(new AcWhitelist(Arrays.asList(url1, url2, url3)))
				.build();
		// all singel permutations
		assertEquals(url1, assertionConsumerService.getAssertionConsumerServiceUrl(url1, null, null, relyingParty));
		assertEquals(url2, assertionConsumerService.getAssertionConsumerServiceUrl(url2, null, null, relyingParty));
		assertEquals(url3, assertionConsumerService.getAssertionConsumerServiceUrl(url3, null, null, relyingParty));
		assertEquals(url1, assertionConsumerService.getAssertionConsumerServiceUrl(null, url1, null, relyingParty));
		assertEquals(url2, assertionConsumerService.getAssertionConsumerServiceUrl(null, url2, null, relyingParty));
		assertEquals(url3, assertionConsumerService.getAssertionConsumerServiceUrl(null, url3, null, relyingParty));
		assertEquals(url1, assertionConsumerService.getAssertionConsumerServiceUrl(null, null, url1, relyingParty));
		assertEquals(url2, assertionConsumerService.getAssertionConsumerServiceUrl(null, null, url2, relyingParty));
		assertEquals(url3, assertionConsumerService.getAssertionConsumerServiceUrl(null, null, url3, relyingParty));
		// near matching
		assertEquals(url2, assertionConsumerService.getAssertionConsumerServiceUrl(url2other, url2host, null, relyingParty));
		assertEquals(url2, assertionConsumerService.getAssertionConsumerServiceUrl(url2other, null, url2host, relyingParty));
		assertEquals(url2, assertionConsumerService.getAssertionConsumerServiceUrl(null, url2other, url2host, relyingParty));
		// denial
		assertThrows(RequestDeniedException.class,
				() -> assertionConsumerService.getAssertionConsumerServiceUrl(null, null, null, relyingParty));
		assertThrows(RequestDeniedException.class,
				() -> assertionConsumerService.getAssertionConsumerServiceUrl(url2other, null, null, relyingParty));
		assertThrows(RequestDeniedException.class,
				() -> assertionConsumerService.getAssertionConsumerServiceUrl(url2port, url2port, url2port, relyingParty));
		assertThrows(RequestDeniedException.class,
				() -> assertionConsumerService.getAssertionConsumerServiceUrl(url2other, url2other, url2other, relyingParty));
	}

	@Test
	void getContextClassesTest() {
		List<String> requestContextClasses = givenRequestContextClasses();
		Qoa qoa = givenQoa();

		List<String> contextClasses = assertionConsumerService.getContextClasses(requestContextClasses, null);
		assertNotNull(contextClasses);
		assertEquals(requestContextClasses.size(), contextClasses.size());


		List<String> contextClasses2 = assertionConsumerService.getContextClasses(requestContextClasses, qoa);
		assertNotNull(contextClasses2);
		assertEquals(requestContextClasses.size(), contextClasses2.size());
		assertNotEquals(qoa.getClasses().size(), contextClasses2.size());

		List<String> contextClasses3 = assertionConsumerService.getContextClasses(new ArrayList<>(), qoa);
		assertNotNull(contextClasses3);
		assertEquals(qoa.getClasses().size(), contextClasses3.size());
		assertNotEquals(0, contextClasses2.size());

		List<String> contextClasses4 = assertionConsumerService.getContextClasses(new ArrayList<>(), null);
		assertNotNull(contextClasses4);
		assertEquals(0, contextClasses4.size());
	}

	@ParameterizedTest
	@CsvSource(value = {
			"false," + StatusCode.RESPONDER + ',' + StatusCode.UNKNOWN_PRINCIPAL + ",message," + StatusCode.RESPONDER + ',' +
					StatusCode.UNKNOWN_PRINCIPAL + ",false",
			"true," + StatusCode.RESPONDER + ',' + StatusCode.UNKNOWN_PRINCIPAL + ",message," + StatusCode.RESPONDER + ',' +
					StatusCode.UNKNOWN_PRINCIPAL + ",true",
			"true," + StatusCode.RESPONDER + ",null," + StatusCode.UNKNOWN_PRINCIPAL + ',' + StatusCode.RESPONDER + ',' +
					StatusCode.UNKNOWN_PRINCIPAL + ",true",
			"true," + StatusCode.RESPONDER + ",null," + StatusCode.UNKNOWN_PRINCIPAL + ',' + StatusCode.AUTHN_FAILED + ',' +
					StatusCode.UNKNOWN_PRINCIPAL + ",false",
			"true," + StatusCode.RESPONDER + ",null," + StatusCode.AUTHN_FAILED + ',' + StatusCode.RESPONDER + ',' +
					StatusCode.UNKNOWN_PRINCIPAL + ",false",
			"true," + StatusCode.RESPONDER + ',' + StatusCode.UNKNOWN_PRINCIPAL + ",message,null," +
					StatusCode.UNKNOWN_PRINCIPAL + ",true",
			"true," + StatusCode.RESPONDER + ',' + StatusCode.AUTHN_FAILED + ",message,null," +
					StatusCode.UNKNOWN_PRINCIPAL + ",false"
	}, nullValues = "null")
	void handleResponderErrors(boolean featureEnabled, String actualStatus, String actualNestedStatus, String actualMessage,
			String requiredStatus, String requiredNestedStatus, boolean expected) {
		doReturn(featureEnabled).when(trustBrokerProperties).isHandleResponderErrors();
		var response = SamlFactory.createResponse(Response.class, "issuerId");
		response.setStatus(SamlFactory.createResponseStatus(actualStatus, actualMessage, actualNestedStatus));
		assertThat(AssertionConsumerService.handleResponderErrors(response, requiredStatus,
				requiredNestedStatus, trustBrokerProperties), is(expected));
	}

	private ClaimsParty mockCp(String cpId, ArtifactBindingMode mode) {
		var cp = ClaimsParty.builder()
				.id(cpId)
				.saml(Saml.builder()
						.artifactBinding(ArtifactBinding.builder().inboundMode(mode).build())
						.build()
				)
				.build();
		doReturn(cp).when(relyingPartySetupService).getClaimsProviderSetupByIssuerId(cpId, null);
		return cp;
	}

	private StateData mockState(String relayState) {
		var stateData = StateData.builder()
				.id("sessionId")
				.spStateData(StateData.builder().id("spSessionId").build())
				.build();
		doReturn(stateData).when(cacheService).find(relayState, AssertionConsumerService.class.getSimpleName());
		return stateData;
	}

	private List<String> givenRequestContextClasses() {
		List<String> contextClasses = new ArrayList<>();
		contextClasses.add(SamlContextClass.MOBILE_ONE_FACTOR_UNREGISTERED);
		return contextClasses;
	}

	private Qoa givenQoa() {
		List<String> contextClasses = new ArrayList<>();
		contextClasses.add(SamlContextClass.MOBILE_ONE_FACTOR_UNREGISTERED);
		contextClasses.add(SamlContextClass.PASSWORD_PROTECTED_TRANSPORT);

		Qoa qoa = new Qoa();
		qoa.setClasses(contextClasses);
		return qoa;
	}

	private void mockRequestConfiguration(String rpId) {
		RelyingPartySetup relyingPartySetup = ServiceSamlTestUtil.loadRelyingPartySetup();
		when(relyingPartyDefinitions.getRelyingPartySetup())
				.thenReturn(relyingPartySetup);
		when(relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(eq(rpId), any()))
				.thenReturn(getRelyingParty(relyingPartySetup, rpId));
	}

	private static RelyingParty getRelyingParty(RelyingPartySetup relyingPartySetup, String id) {
		return relyingPartySetup.getRelyingParties().stream()
				.filter(rp -> id.equals(rp.getId()))
				.findFirst()
				.orElseThrow(() -> new IllegalArgumentException("Missing RP " + id));
	}

	private void mockSecurityChecks(boolean requireSignedResponse, boolean requireSignedAssertion, boolean validateRelayState,
			boolean validateResponseIssuer) {
		var secChecks = new SecurityChecks();
		secChecks.setRequireSignedResponse(requireSignedResponse);
		secChecks.setValidateRelayState(validateRelayState);
		secChecks.setValidateResponseIssuer(validateResponseIssuer);
		secChecks.setRequireSignedAssertion(requireSignedAssertion);
		doReturn(secChecks).when(trustBrokerProperties).getSecurity();
	}

}
