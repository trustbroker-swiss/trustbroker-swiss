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
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.io.UnsupportedEncodingException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import jakarta.servlet.http.Cookie;
import org.apache.xml.security.utils.EncryptionConstants;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.SessionIndex;
import org.opensaml.saml.saml2.core.StatusCode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import swiss.trustbroker.api.accessrequest.dto.AccessRequestHttpData;
import swiss.trustbroker.api.accessrequest.dto.AccessRequestResult;
import swiss.trustbroker.api.accessrequest.service.AccessRequestService;
import swiss.trustbroker.api.idm.dto.IdmRequests;
import swiss.trustbroker.api.idm.dto.IdmResult;
import swiss.trustbroker.api.idm.service.IdmService;
import swiss.trustbroker.api.idm.service.IdmStatusPolicyCallback;
import swiss.trustbroker.api.profileselection.dto.ProfileSelectionData;
import swiss.trustbroker.api.profileselection.dto.ProfileSelectionResult;
import swiss.trustbroker.api.profileselection.service.ProfileSelectionService;
import swiss.trustbroker.api.qoa.service.QualityOfAuthenticationService;
import swiss.trustbroker.api.relyingparty.dto.RelyingPartyConfig;
import swiss.trustbroker.api.sessioncache.dto.CpResponseData;
import swiss.trustbroker.audit.service.AuditService;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.saml.dto.SamlBinding;
import swiss.trustbroker.common.saml.dto.SignatureContext;
import swiss.trustbroker.common.saml.service.ArtifactCacheService;
import swiss.trustbroker.common.saml.util.CoreAttributeInitializer;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.common.saml.util.SamlIoUtil;
import swiss.trustbroker.config.TrustBrokerConfiguration;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.ArtifactResolution;
import swiss.trustbroker.config.dto.OidcProperties;
import swiss.trustbroker.config.dto.SamlProperties;
import swiss.trustbroker.config.dto.SecurityChecks;
import swiss.trustbroker.federation.xmlconfig.AccessRequest;
import swiss.trustbroker.federation.xmlconfig.ArtifactBinding;
import swiss.trustbroker.federation.xmlconfig.ArtifactBindingMode;
import swiss.trustbroker.federation.xmlconfig.AttributesSelection;
import swiss.trustbroker.federation.xmlconfig.AuthorizedApplications;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.Encryption;
import swiss.trustbroker.federation.xmlconfig.Flow;
import swiss.trustbroker.federation.xmlconfig.IdmLookup;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.Saml;
import swiss.trustbroker.federation.xmlconfig.SecurityPolicies;
import swiss.trustbroker.federation.xmlconfig.SloResponse;
import swiss.trustbroker.federation.xmlconfig.Sso;
import swiss.trustbroker.federation.xmlconfig.SubjectName;
import swiss.trustbroker.federation.xmlconfig.SubjectNameMappings;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.homerealmdiscovery.util.DefaultIdmStatusPolicyCallback;
import swiss.trustbroker.qoa.dto.NoOpQoa;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.saml.dto.ResponseData;
import swiss.trustbroker.saml.test.util.ServiceSamlTestUtil;
import swiss.trustbroker.saml.util.ResponseFactory;
import swiss.trustbroker.script.service.ScriptService;
import swiss.trustbroker.sessioncache.dto.SsoSessionParticipant;
import swiss.trustbroker.sessioncache.dto.SsoState;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.sessioncache.service.StateCacheService;
import swiss.trustbroker.sso.dto.SloNotification;
import swiss.trustbroker.sso.service.SsoService;
import swiss.trustbroker.test.saml.util.SamlTestBase;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.HrdSupport;
import swiss.trustbroker.util.WebSupport;

@SpringBootTest
@ContextConfiguration(classes = {
		RelyingPartyService.class,
		TrustBrokerConfiguration.class,
		ApiSupport.class,
		SamlOutputService.class
})
@TestPropertySource(properties = "trustbroker.config.devmode.enabled=false")
class RelyingPartyServiceTest extends ServiceTestBase {

	private static final String COOKIE_NAME = "sessionCookie";

	private static final String COOKIE_NAME2 = "sessionCookie2";

	private static final String RELAY_STATE = "relayStateRp";

	private static final String REFERRER = "http://localhost/logout";

	private static final String SLO_URL = "http://localhost/slo";

	private static final String DESTINATION_URL = "http://localhost/acs";

	private static final String CLIENT_EXT_ID = "clientExtId";

	private static final String CP_ISSUER_ID = "cpIssuerId";

	private static final String HOME_NAME = "homeNameUrn";

	private static final String USER_NAME_ID = "userNameId";

	private static final String RP_ISSUER_ID = "rpIssuerId";

	private static final String ISSUER_ID = "selfIssuerId";

	private static final String CLIENT_ID = "clientId";

	private static final String PERIMETER_URL = "http://test.trustbroker.swiss";

	private static final String IDENTITY_QUERY = "IDENTITY";

	@MockBean
	private TrustBrokerProperties trustBrokerProperties;

	@MockBean
	private RelyingPartySetupService relyingPartySetupService;

	@MockBean
	private IdmService idmService;

	@MockBean
	ScriptService scriptService;

	@MockBean
	@Qualifier("stateCache")
	private StateCacheService cacheService;

	@MockBean
	private ProfileSelectionService profileSelectionService;

	@MockBean
	private SsoService ssoService;

	@MockBean
	private AuditService auditService;

	@MockBean
	private AccessRequestService accessRequestService;

	@MockBean
	private ResponseFactory responseFactory;

	@MockBean
	private StateCacheService stateCacheService;

	@MockBean
	private ArtifactCacheService artifactCacheService;

	@MockBean
	private UnknownUserPolicyService unknownUserPolicyService;

	@MockBean
	private QualityOfAuthenticationService qoaService;

	@Autowired
	private SamlOutputService outputService;

	@Autowired
	private RelyingPartyService relyingPartyService;

	private ServiceSamlTestUtil samlTestUtil = new ServiceSamlTestUtil();

	@BeforeAll
	static void setup() {
		SamlInitializer.initSamlSubSystem();

		new CoreAttributeInitializer().init();

		// testAddAllProperties needs this:
		SamlTestBase.setAnyAttributeNamespaceUri(CoreAttributeName.HOME_NAME);
		SamlTestBase.setAnyAttributeNamespaceUri(CoreAttributeName.HOME_REALM);
		SamlTestBase.setAnyAttributeNamespaceUri(CoreAttributeName.ISSUED_CLIENT_EXT_ID);
		SamlTestBase.setAnyAttributeNamespaceUri(CoreAttributeName.AUTH_LEVEL);
		SamlTestBase.setAnyAttributeNamespaceUri(CoreAttributeName.SSO_SESSION_ID);
	}

	@BeforeEach
	void setupMocks() {
		doReturn(NoOpQoa.UNSPECIFIED).when(qoaService).getUnspecifiedAuthLevel();
	}

	@ParameterizedTest
	@CsvSource(value = { "true,true", "false,false", "false,true" })
	void handleLogoutRequest(boolean succeedLogout, boolean isStatePresent) throws UnsupportedEncodingException {
		var request = new MockHttpServletRequest();
		var response = new MockHttpServletResponse();
		var logoutRequest = setupMockData(request, succeedLogout, isStatePresent, null);

		var signatureContext = SignatureContext.forPostBinding();
		relyingPartyService.handleLogoutRequest(outputService, logoutRequest, RELAY_STATE, request, response, signatureContext);

		// we always send a success response
		var expectedContent = new ArrayList<String>();
		expectedContent.add(RELAY_STATE);
		assertContent(response, StatusCode.SUCCESS, expectedContent);
	}

	@ParameterizedTest
	@MethodSource
	void handleLogoutRequestInvalidBinding(ArtifactBindingMode mode, SignatureContext signatureContext) {
		var request = new MockHttpServletRequest();
		var response = new MockHttpServletResponse();
		var logoutRequest = setupMockData(request, Boolean.valueOf(true), true, mode);

		var ex = assertThrows(RequestDeniedException.class, () -> relyingPartyService.handleLogoutRequest(outputService,
				logoutRequest, RELAY_STATE,	request, response, signatureContext));
		assertThat(ex.getInternalMessage(), containsString("does not support inbound binding"));
	}

	static Object[][] handleLogoutRequestInvalidBinding() {
		return new Object[][] {
				{ ArtifactBindingMode.NOT_SUPPORTED, SignatureContext.forArtifactBinding() },
				{ ArtifactBindingMode.REQUIRED, SignatureContext.forPostBinding() },
				{ ArtifactBindingMode.REQUIRED, SignatureContext.forRedirectBinding("") }
		};
	}

	@Test
	void testAddAllProperties() {
		String issuer = "SAMPLE-CP";
		String clientExtId = "1234";
		String homeName = "Test-Login";
		String nameId = "id/232";
		String authnvalue = "authnvalue";
		String ssoSessionIdValue = "test-sso-session-uuid";
		CpResponse cpResponse = givenCpResponse(issuer, clientExtId, homeName, nameId, false);
		when(relyingPartySetupService.getCpAuthLevel(any(), any())).thenReturn(authnvalue);

		int initialPropertiesSize = cpResponse.getProperties().size();
		var stateDate = StateData.builder().id("test-sess-id").ssoSessionId(ssoSessionIdValue).build();
		relyingPartyService.setProperties(cpResponse);
		RelyingPartyService.adjustSsoSessionIdProperty(stateDate, cpResponse);

		var properties = cpResponse.getProperties();
		int propertiesSize = properties.size();

		assertEquals(0, initialPropertiesSize);
		assertTrue(propertiesSize > initialPropertiesSize);
		assertEquals(5, propertiesSize);

		String attributeHomeRealm = cpResponse.getProperty(CoreAttributeName.HOME_REALM.getNamespaceUri());
		String attributeHomeName = cpResponse.getProperty(CoreAttributeName.HOME_NAME.getNamespaceUri());
		String attributeClientExtId = cpResponse.getProperty(CoreAttributeName.ISSUED_CLIENT_EXT_ID.getNamespaceUri());
		String attributeAuthLevel = cpResponse.getProperty(CoreAttributeName.AUTH_LEVEL.getNamespaceUri());
		String attributeSsoSessionId = cpResponse.getProperty(CoreAttributeName.SSO_SESSION_ID.getNamespaceUri());

		assertEquals(attributeHomeName, homeName);
		assertEquals(attributeHomeRealm, issuer);
		assertEquals(attributeClientExtId, clientExtId);
		assertEquals(attributeAuthLevel, authnvalue);
		assertEquals(attributeSsoSessionId, ssoSessionIdValue);
	}

	@Test
	void testFilterProperties() {
		String issuer = "SAMPLE-CP";
		String clientExtId = "1234";
		String homeName = "TEST-Login";
		String nameId = "id/232";
		CpResponse cpResponse = givenCpResponse(issuer, clientExtId, homeName, nameId, true);
		AttributesSelection attributesSelection = givenAttributesSelection();
		when(relyingPartySetupService.getPropertiesAttrSelection(any(), any())).thenReturn(attributesSelection);

		relyingPartyService.filterPropertiesSelection(cpResponse, "test", "test");

		Map<Definition, List<String>> definitionListMap = cpResponse.getProperties();
		int propertiesSize = definitionListMap.size();

		assertEquals(1, propertiesSize);
		List<String> definitionNames = definitionListMap.keySet().stream()
				.map(Definition::getName)
				.collect(Collectors.toList());
		assertTrue(definitionNames.contains(CoreAttributeName.HOME_REALM.getName()));
		assertFalse(definitionNames.contains(CoreAttributeName.HOME_NAME.getName()));
		assertFalse(definitionNames.contains(CoreAttributeName.ISSUED_CLIENT_EXT_ID.getName()));
		assertFalse(definitionNames.contains(CoreAttributeName.EMAIL.getName()));
	}

	@ParameterizedTest
	@CsvSource(value = { "false", "true" })
	void testPerformSilentAccessRequestDone(boolean fallback) {
		var spStateData = buildSpStateData();
		var rpIssuer = "rpIssuer1";
		spStateData.setIssuer(rpIssuer);
		var stateData = buildStateData("group1", "idx1", spStateData, Collections.emptySet(), null);
		var request = new MockHttpServletRequest();
		var relyingParty = RelyingParty
				.builder()
				.id("rp1")
				.accessRequest(AccessRequest
						.builder()
						.authorizedApplications(AuthorizedApplications
								.builder()
								.build())
						.build())
				.build();
		var idmLookup = IdmLookup
				.builder()
				.build();
		var cpResponse = CpResponse
				.builder()
				.rpIssuer("rp2")
				.idmLookup(idmLookup)
				.build();
		stateData.setCpResponse(cpResponse);
		var url = fallback ? "https://localhost/initiate" : null;
		var httpData = AccessRequestHttpData.of(request);

		doReturn(AccessRequestResult.of(true, false, null))
				.when(accessRequestService).performAccessRequestIfRequired(httpData, relyingParty, stateData);
		doReturn(AccessRequestResult.of(false, false, url))
				.when(accessRequestService).performFallbackAccessRequestIfRequired(httpData, relyingParty, stateData);

		// url is returned by fallback
		assertThat(relyingPartyService.performAccessRequestIfRequired(request, relyingParty, stateData, null),
				is(url));

		// initial refresh and refresh after AR
		var relyingPartyConfig = ArgumentCaptor.forClass(RelyingPartyConfig.class);
		var cpResponseData = ArgumentCaptor.forClass(CpResponseData.class);
		var queryData = ArgumentCaptor.forClass(IdmRequests.class);
		var callback = ArgumentCaptor.forClass(IdmStatusPolicyCallback.class);
		verify(idmService, times(2)).getAttributesFromIdm(relyingPartyConfig.capture(),
				cpResponseData.capture(), queryData.capture(), callback.capture());
		assertThat(relyingPartyConfig.getValue().getId(), is(rpIssuer));
		assertThat(cpResponseData.getValue().getIssuerId(), is(cpResponse.getIssuer()));
		assertThat(queryData.getValue().getQueryList(), hasSize(idmLookup.getQueries().size()));
		assertThat(callback.getValue(), instanceOf(DefaultIdmStatusPolicyCallback.class));
		if (fallback) {
			verify(cacheService).save(stateData, RelyingPartyService.class.getSimpleName());
		}
		else {
			verifyNoInteractions(cacheService);
		}
	}

	@ParameterizedTest
	@MethodSource
	void testPerformInteractiveAccessRequestRequired(boolean retainSession, String url) {
		var stateData = givenState(ISSUER_ID);
		stateData.setCpResponse(CpResponse.builder().rpIssuer(ISSUER_ID).build());
		var request = new MockHttpServletRequest();
		var relyingParty = RelyingParty.builder().id(ISSUER_ID).build();
		var httpData = AccessRequestHttpData.of(request);

		doReturn(AccessRequestResult.of(false, retainSession, url))
				.when(accessRequestService).performAccessRequestIfRequired(httpData, relyingParty, stateData);

		assertThat(relyingPartyService.performAccessRequestIfRequired(request, relyingParty, stateData, null), is(url));
		if (retainSession) {
			verify(ssoService).establishImplicitSso(relyingParty, stateData);
			verifyNoInteractions(cacheService);
		}
		else {
			verifyNoInteractions(ssoService);
			verify(cacheService).save(stateData, RelyingPartyService.class.getSimpleName());
		}
		verifyNoInteractions(idmService);
	}

	static Object[][] testPerformInteractiveAccessRequestRequired() {
		return new Object[][] {
				{ false, "https://localhost/redirect" },
				{ true, null }
		};
	}

	@Test
	void testSkipInteractiveAccessRequest() {
		var stateData = givenState(ISSUER_ID);
		stateData.setCpResponse(CpResponse.builder().rpIssuer(ISSUER_ID).build());
		var request = new MockHttpServletRequest();
		var relyingParty = RelyingParty.builder().id(ISSUER_ID).build();
		request.addHeader(HrdSupport.HTTP_URLTESTER_CP, "anycp");
		var httpData = AccessRequestHttpData.of(request);

		doReturn(AccessRequestResult.of(false, false, DESTINATION_URL))
				.when(accessRequestService).performAccessRequestIfRequired(httpData, relyingParty, stateData);

		assertThat(relyingPartyService.performAccessRequestIfRequired(request, relyingParty, stateData, null), nullValue());
	}

	@Test
	void testNoAccessRequestRequired() {
		var stateData = givenState(ISSUER_ID);
		stateData.setCpResponse(CpResponse.builder().rpIssuer(ISSUER_ID).build());
		var request = new MockHttpServletRequest();
		var relyingParty = RelyingParty.builder().id(ISSUER_ID).build();
		var httpData = AccessRequestHttpData.of(request);

		doReturn(AccessRequestResult.of(false, false, null))
				.when(accessRequestService).performAccessRequestIfRequired(httpData, relyingParty, stateData);

		assertThat(relyingPartyService.performAccessRequestIfRequired(request, relyingParty, stateData, null),
				is(nullValue()));

		verifyNoInteractions(cacheService);

		verifyNoInteractions(idmService);
	}

	@ParameterizedTest
	@CsvSource(value = {
			"false,true,true,false,false",
			"true,false,false,true,true",
			"null,true,false,true,false"
	}, nullValues = "null")
	void testSignResponse(Boolean requireSignedResponse, boolean signSuccessResponse, boolean signFailureResponse,
			boolean expectedSignSuccessResponse, boolean expectedSignFailureResponse) {
		var secPol = SecurityPolicies.builder().requireSignedResponse(requireSignedResponse).build();
		var relyingParty = RelyingParty.builder().id("rp1").securityPolicies(secPol).build();
		var secChecks = new SecurityChecks();
		secChecks.setDoSignSuccessResponse(signSuccessResponse);
		secChecks.setDoSignFailureResponse(signFailureResponse);
		doReturn(secChecks).when(trustBrokerProperties).getSecurity();

		assertThat(relyingPartyService.signFailureResponse(relyingParty), is(expectedSignFailureResponse));
		assertThat(relyingPartyService.signSuccessResponse(relyingParty), is(expectedSignSuccessResponse));
	}

	@Test
	void testSetAssertionNoEncryption() {
		var authnResponse = givenResponseWithoutAssertion();
		var assertion = givenAssertion();
		var relyingParty = givenMockedRelyingParty(false);
		givenMockedOidcProperties(PERIMETER_URL);

		relyingPartyService.setAssertion(authnResponse, assertion, relyingParty);
		assertNotNull(authnResponse.getAssertions());
		assertNotNull(authnResponse.getAssertions().get(0));
		assertEquals(1, authnResponse.getAssertions().size());
	}

	@Test
	void testSetAssertionEncryptionWithDefaults() {
		Response authnResponse = givenResponseWithoutAssertion();
		Assertion assertion = givenAssertion();
		RelyingParty relyingParty = givenRelyingPartyWithEncryptionCred();
		givenMockedOidcProperties(PERIMETER_URL);

		relyingPartyService.setAssertion(authnResponse, assertion, relyingParty);
		expectedResult(authnResponse, EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256,
				EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
	}

	@Test
	void testSetAssertionEncryption() {
		Response authnResponse = givenResponseWithoutAssertion();
		Assertion assertion = givenAssertion();
		String dataEncryAlg = EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES192;
		String keyEncryAlg = EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP_11;
		givenMockedOidcProperties(PERIMETER_URL);
		RelyingParty relyingParty = givenRelyingPartyWithEncryption(dataEncryAlg, keyEncryAlg);

		relyingPartyService.setAssertion(authnResponse, assertion, relyingParty);
		expectedResult(authnResponse, dataEncryAlg, keyEncryAlg);
	}

	@Test
	void sendAbortedSamlResponseToRpWithConfirmation() {
		var authnResponse = givenResponseWithoutAssertion();
		var responseData = ResponseData.of(authnResponse, RELAY_STATE, null);
		var cpResponse = givenCpResponse(CP_ISSUER_ID, CLIENT_EXT_ID, HOME_NAME, USER_NAME_ID, false);
		cpResponse.setStatusCode("responderCode");
		cpResponse.setFlowPolicy(Flow.builder().id("denied").appContinue(true).build());
		WebSupport.setTraceContext("traceId");
		var stateData = givenState(RP_ISSUER_ID);
		doReturn(stateData).when(stateCacheService).find(RELAY_STATE, RelyingPartyService.class.getSimpleName());
		var mockHttpRequest = new MockHttpServletRequest();
		var mockHttpResponse = new MockHttpServletResponse();
		var result = relyingPartyService.sendSuccessSamlResponseToRp(outputService, responseData, cpResponse, stateData,
				mockHttpRequest,
				mockHttpResponse, null);
		assertThat(result, is("/app/failure/denied/traceId/" + ApiSupport.encodeUrlParameter("sessionId") + "/continue"));
	}

	@Test
	void sendAbortedSamlResponseToRp() throws Exception {
		var authnResponse = givenResponseWithoutAssertion();
		var responseData = ResponseData.of(authnResponse, RELAY_STATE, null);
		givenMockedRelyingParty(false);
		var cpResponse = givenCpResponse(CP_ISSUER_ID, CLIENT_EXT_ID, HOME_NAME, USER_NAME_ID, false);
		cpResponse.setStatusCode(StatusCode.RESPONDER);
		cpResponse.setRpDestination(DESTINATION_URL);
		var nestedCode = "statusNestedCodeId";
		var statusMessage = "lorem ipsum dolor";
		cpResponse.setStatusNestedCode(nestedCode);
		cpResponse.setStatusMessage(statusMessage);
		var stateData = givenState(RP_ISSUER_ID);
		var mockHttpRequest = new MockHttpServletRequest();
		var mockHttpResponse = new MockHttpServletResponse();
		doReturn(stateData).when(stateCacheService).find(RELAY_STATE, RelyingPartyService.class.getSimpleName());
		mockSecurityChecks();
		var result = relyingPartyService.sendSuccessSamlResponseToRp(outputService, responseData, cpResponse, stateData,
				mockHttpRequest, mockHttpResponse, null);
		assertThat(result, is(nullValue()));
		var response = samlTestUtil.extractSamlPostResponse(mockHttpResponse.getContentAsString());
		assertThat(response.getStatus().getStatusCode().getValue(), is(StatusCode.RESPONDER));
		assertThat(response.getStatus().getStatusCode().getStatusCode().getValue(), is(nestedCode));
		assertThat(response.getStatus().getStatusMessage().getValue(), is(statusMessage));
	}

	@ParameterizedTest
	@CsvSource(value = { "false", "true" })
	void sendSuccessSamlResponseToRp(boolean useArtifactBinding) throws Exception {
		var authnResponse = givenResponseWithoutAssertion();
		givenMockedOidcProperties(PERIMETER_URL);
		var responseData = ResponseData.of(authnResponse, RELAY_STATE, null);
		var relyingParty = givenMockedRelyingParty(useArtifactBinding);
		var cpResponse = givenCpResponse(CP_ISSUER_ID, CLIENT_EXT_ID, HOME_NAME, USER_NAME_ID, false);
		cpResponse.setRpDestination(DESTINATION_URL);
		var stateData = givenState(RP_ISSUER_ID);
		stateData.getSpStateData().setOidcClientId(CLIENT_ID);
		var mockHttpRequest = new MockHttpServletRequest();
		var mockHttpResponse = new MockHttpServletResponse();
		mockSecurityChecks();
		givenMockedClaimsParty();
		var arResult = AccessRequestResult.of(false, false, null);
		var httpData = AccessRequestHttpData.of(mockHttpRequest);
		doReturn(arResult).when(accessRequestService).performAccessRequestIfRequired(httpData, relyingParty, stateData);
		doReturn(ProfileSelectionResult.empty()).when(profileSelectionService).doInitialProfileSelection(
				ProfileSelectionData.builder().exchangeId(RELAY_STATE).oidcClientId(CLIENT_ID).build(),
				relyingParty, cpResponse, stateData);
		var result = relyingPartyService.sendSuccessSamlResponseToRp(outputService, responseData, cpResponse, stateData,
				mockHttpRequest, mockHttpResponse, null);
		assertThat(result, is(nullValue()));
		validateResponse(useArtifactBinding, StatusCode.SUCCESS, mockHttpResponse);
	}

	@ParameterizedTest
	@CsvSource(value = { "false", "true" })
	void sendFailedSamlResponseToRp(boolean useArtifactBinding) throws Exception {
		var authnResponse = givenResponseWithoutAssertion();
		var statusCode = StatusCode.AUTHN_FAILED;
		var status = SamlFactory.createResponseStatus(statusCode);
		authnResponse.setStatus(status);
		givenMockedOidcProperties(PERIMETER_URL);
		var responseData = ResponseData.of(authnResponse, RELAY_STATE, null);
		givenMockedRelyingParty(useArtifactBinding);
		var cpResponse = givenCpResponse(CP_ISSUER_ID, CLIENT_EXT_ID, HOME_NAME, USER_NAME_ID, false);
		cpResponse.setRpDestination(DESTINATION_URL);
		var stateData = givenState(RP_ISSUER_ID);
		doReturn(stateData).when(stateCacheService).find(RELAY_STATE, RelyingPartyService.class.getSimpleName());
		var mockHttpRequest = new MockHttpServletRequest();
		var mockHttpResponse = new MockHttpServletResponse();
		mockSecurityChecks();
		var result = relyingPartyService.sendFailedSamlResponseToRp(outputService, responseData, mockHttpRequest,
				mockHttpResponse, cpResponse);
		assertThat(result, is(nullValue()));
		validateResponse(useArtifactBinding, statusCode, mockHttpResponse);
	}

	@ParameterizedTest
	@CsvSource(value = {
			// ArtifactBinding is independent of the IDM flags
			"false,true,true,true,true",
			"false,true,true,false,false",
			"true,false,false,false,true",
			"true,true,false,false,false"
	})
	void sendAuthnResponseToRpFromState(boolean useArtifactBinding, boolean sameRp, boolean ssoEnabled, boolean forceIdmFetch,
			boolean expectIdmRefresh)
			throws Exception {
		var relyingParty = givenMockedRelyingParty(useArtifactBinding);
		relyingParty.setSso(Sso.builder().enabled(ssoEnabled).forceIdmRefresh(forceIdmFetch).build());
		givenMockedOidcProperties(PERIMETER_URL);
		mockSecurityChecks();
		var stateData = givenState(RP_ISSUER_ID);
		stateData.getSpStateData().setRelayState(RELAY_STATE);
		stateData.getSpStateData().setOidcClientId(CLIENT_ID);
		doReturn(stateData).when(stateCacheService).find(RELAY_STATE, RelyingPartyService.class.getSimpleName());
		var ssoStateData = givenState(RP_ISSUER_ID);
		var cpResponse = givenCpResponse(CP_ISSUER_ID, CLIENT_EXT_ID, HOME_NAME, USER_NAME_ID, false);
		if (sameRp) {
			cpResponse.setRpIssuer(RP_ISSUER_ID);
		}
		cpResponse.setRpDestination(DESTINATION_URL);
		ssoStateData.setCpResponse(cpResponse);
		ssoStateData.setSelectedProfileExtId(PROFILE_ID);
		var profileSelectionData = ProfileSelectionData.builder()
				.oidcClientId(CLIENT_ID)
				.exchangeId(RELAY_STATE)
				.selectedProfileId(PROFILE_ID)
				.build();
		doReturn(ProfileSelectionResult.empty()).when(profileSelectionService).doSsoProfileSelection(
				profileSelectionData, relyingParty, cpResponse, stateData);
		var mockHttpRequest = new MockHttpServletRequest();
		var mockHttpResponse = new MockHttpServletResponse();
		var result = relyingPartyService.sendAuthnResponseToRpFromState(outputService, mockHttpRequest, mockHttpResponse,
				ssoStateData, stateData);
		assertThat(result, is(nullValue()));
		validateResponse(useArtifactBinding, StatusCode.SUCCESS, mockHttpResponse);
		verify(ssoService).completeDeviceInfoPreservingStateForSso(ssoStateData, stateData, relyingParty);
		if (expectIdmRefresh) {
			var relyingPartyConfig = ArgumentCaptor.forClass(RelyingPartyConfig.class);
			var cpResponseData = ArgumentCaptor.forClass(CpResponseData.class);
			var queryData = ArgumentCaptor.forClass(IdmRequests.class);
			var callback = ArgumentCaptor.forClass(IdmStatusPolicyCallback.class);
			verify(idmService, times(1)).getAttributesFromIdm(relyingPartyConfig.capture(),
					cpResponseData.capture(), queryData.capture(), callback.capture());
			assertThat(relyingPartyConfig.getValue().getId(), is(RP_ISSUER_ID));
			assertThat(cpResponseData.getValue().getIssuerId(), is(CP_ISSUER_ID));
			assertThat(queryData.getValue().getQueryList(), hasSize(3));
			assertThat(queryData.getValue().getQueryList().get(0).getName(), is(IDENTITY_QUERY));
			assertThat(callback.getValue(), instanceOf(DefaultIdmStatusPolicyCallback.class));
		}
		else {
			verifyNoInteractions(idmService);
		}
	}

	@ParameterizedTest
	@CsvSource(value = { "false", "true" })
	void sendResponseWithSamlResponseFromCp(boolean useArtifactBinding) throws Exception {
		var authnResponse = givenResponseWithoutAssertion();
		var responseData = ResponseData.of(authnResponse, RELAY_STATE, null);
		var relyingParty = givenMockedRelyingParty(useArtifactBinding);
		givenMockedOidcProperties(PERIMETER_URL);
		mockSecurityChecks();
		var stateData = givenState(RP_ISSUER_ID);
		stateData.getSpStateData().setOidcClientId(CLIENT_ID);
		doReturn(stateData).when(stateCacheService).find(RELAY_STATE, RelyingPartyService.class.getSimpleName());
		var cpResponse = givenCpResponse(CP_ISSUER_ID, CLIENT_EXT_ID, HOME_NAME, USER_NAME_ID, false);
		cpResponse.setRpDestination(DESTINATION_URL);
		givenMockedClaimsParty();
		var mockHttpRequest = new MockHttpServletRequest();
		var mockHttpResponse = new MockHttpServletResponse();
		var arResult = AccessRequestResult.of(false, false, null);
		var httpData = AccessRequestHttpData.of(mockHttpRequest);
		doReturn(arResult).when(accessRequestService).performAccessRequestIfRequired(httpData, relyingParty, stateData);
		doReturn(ProfileSelectionResult.empty()).when(profileSelectionService).doInitialProfileSelection(
				ProfileSelectionData.builder().exchangeId(RELAY_STATE).oidcClientId(CLIENT_ID).build(),
				relyingParty, cpResponse, stateData);
		var result = relyingPartyService.sendResponseWithSamlResponseFromCp(outputService, responseData, cpResponse,
				mockHttpRequest, mockHttpResponse);
		assertThat(result, is(nullValue()));
		validateResponse(useArtifactBinding, StatusCode.SUCCESS, mockHttpResponse);
	}

	@Test
	void reloadIdmDataAndValidateAccessRequestSuccess() {
		var relyingParty = givenMockedRelyingParty(false);
		var stateData = givenStateDataWithCpResponse();
		doReturn(Optional.of(new IdmResult())).when(idmService).getAttributesFromIdm(any(), any(), any(), any());

		relyingPartyService.reloadIdmDataAndValidateAccessRequestSuccess(relyingParty, stateData);

		verify(accessRequestService).requireAccessRequest(relyingParty, stateData);
	}

	@Test
	void reloadIdmDataAndValidateAccessRequestFailure() {
		var relyingParty = givenMockedRelyingParty(false);
		var stateData = givenStateDataWithCpResponse();
		doReturn(Optional.of(new IdmResult())).when(idmService).getAttributesFromIdm(any(), any(), any(), any());
		doReturn(true).when(accessRequestService).requireAccessRequest(relyingParty, stateData);

		assertThrows(RequestDeniedException.class,
				() -> relyingPartyService.reloadIdmDataAndValidateAccessRequestSuccess(relyingParty, stateData));
	}

	@Test
	void adjustSubjectNameId() {
		var expectedSubjectNameIdFrom = CoreAttributeName.EMAIL.getNamespaceUri();
		var cpIssuer = "cpIssuer1";
		var subjectNameMappings =
				SubjectNameMappings.builder()
								   .subjects(List.of(
										   SubjectName.builder()
													  .issuer(cpIssuer) // mapped if from this CP
													  .source(expectedSubjectNameIdFrom)
													  .format("from-config-0")
													  .build(),
										   SubjectName.builder()
													  .issuer(null) // mapped from any CP
													  .source("source-without-value")
													  .format("from-config-1")
													  .build(),
										   SubjectName.builder()
													  .issuer("cpIssuer2")
													  .issuer(null)
													  .source(expectedSubjectNameIdFrom)
													  .format("from-config-2")
													  .build())
								   )
								   .build();
		var relyingParty = RelyingParty.builder()
									   .id("rpIssuer1")
									   .subjectNameMappings(subjectNameMappings)
									   .build();
		var userDetails = Map.of(Definition.builder()
										   .name("anyAuditName")
										   .namespaceUri(expectedSubjectNameIdFrom)
										   .build(), List.of("me@trustbroker.swiss"));
		// modified and logged
		var cpResponse0 = CpResponse.builder()
									.issuer("cpIssuer1")
									.originalNameId("initial")
									.nameId("initial")
									.nameIdFormat("from-idp")
									.userDetails(userDetails)
									.build();
		relyingPartyService.adjustSubjectNameId(cpResponse0, relyingParty);
		assertThat(cpResponse0.getNameId(), is("me@trustbroker.swiss"));
		assertThat(cpResponse0.getNameIdFormat(), is("from-config-0"));

		// not modified as already manipulated but manipulation is logged
		var cpResponse1 = CpResponse.builder()
									.issuer("cpIssuer2")
									.originalNameId("initial")
									.nameId("modified-by-idm")
									.nameIdFormat("from-idp")
									.userDetails(userDetails)
									.build();
		relyingPartyService.adjustSubjectNameId(cpResponse1, relyingParty);
		assertThat(cpResponse1.getNameId(), is("modified-by-idm"));
		assertThat(cpResponse1.getNameIdFormat(), is("from-idp"));
	}

	private StateData givenStateDataWithCpResponse() {
		var stateData = givenState(RP_ISSUER_ID);
		var cpResponse = givenCpResponse(CP_ISSUER_ID,  null, null, null, false);
		stateData.setCpResponse(cpResponse);
		stateData.setIssuer(CP_ISSUER_ID);
		return stateData;
	}

	private void validateResponse(boolean useArtifactBinding, String statusCode, MockHttpServletResponse mockHttpResponse)
			throws UnsupportedEncodingException {
		if (useArtifactBinding) {
			var response = samlTestUtil.extractSamlArtifactValue(mockHttpResponse.getContentAsString());
			assertThat(response, is(not(nullValue())));
			var sourceId = OpenSamlUtil.extractSourceIdFromArtifactId(response);
			assertThat(sourceId, is(OpenSamlUtil.calculateArtifactSourceIdFromIssuerId(ISSUER_ID)));
		}
		else {
			var response = samlTestUtil.extractSamlPostResponse(mockHttpResponse.getContentAsString());
			assertThat(response.getStatus().getStatusCode().getValue(), is(statusCode));
		}
	}

	private void mockArtifactBinding() {
		var samlProperties = new SamlProperties();
		var ar = new ArtifactResolution();
		ar.setIndex(0);
		ar.setServiceUrl("http://localhost:1/arp");
		samlProperties.setArtifactResolution(ar);
		doReturn(samlProperties).when(trustBrokerProperties).getSaml();
		doReturn(ISSUER_ID).when(trustBrokerProperties).getIssuer();
		var artifactMap = OpenSamlUtil.createArtifactMap();
		doReturn(artifactMap).when(artifactCacheService).getArtifactMap();
	}

	@ParameterizedTest
	@MethodSource
	void useArtifactBinding(ArtifactBindingMode mode, SamlBinding binding, Boolean rpSessionInit,
			Boolean cpSessionInit, boolean result) {
		var relyingParty = givenMockedRelyingParty(false);
		if (mode != null) {
			relyingParty.setSaml(
					Saml.builder()
							.artifactBinding(ArtifactBinding.builder().outboundMode(mode).build())
							.build());
		}
		var stateData = (rpSessionInit != null || cpSessionInit != null) ? givenState(RP_ISSUER_ID) : null;
		if (stateData != null) {
			stateData.getSpStateData().setInitiatedViaArtifactBinding(rpSessionInit);
			stateData.setInitiatedViaArtifactBinding(cpSessionInit);
		}
		assertThat(RelyingPartyService.useArtifactBinding(relyingParty, stateData, binding), is(result));
	}

	static Object[][] useArtifactBinding() {
		return new Object[][] {
				{ null, null, null, null, false },
				{ null, SamlBinding.ARTIFACT, Boolean.TRUE, Boolean.FALSE, false },
				{ ArtifactBindingMode.NOT_SUPPORTED, null, null, null, false },
				{ ArtifactBindingMode.NOT_SUPPORTED, SamlBinding.ARTIFACT, Boolean.TRUE, Boolean.FALSE, false },
				{ ArtifactBindingMode.NOT_SUPPORTED, SamlBinding.ARTIFACT, Boolean.FALSE, Boolean.TRUE, false },
				{ ArtifactBindingMode.REQUIRED, null, null, null, true },
				{ ArtifactBindingMode.REQUIRED, SamlBinding.ARTIFACT, Boolean.TRUE, Boolean.FALSE, true },
				{ ArtifactBindingMode.REQUIRED, SamlBinding.ARTIFACT, Boolean.FALSE, Boolean.TRUE, true },
				{ ArtifactBindingMode.REQUIRED, SamlBinding.POST, Boolean.FALSE, Boolean.FALSE, true },
				{ ArtifactBindingMode.REQUIRED, SamlBinding.REDIRECT, Boolean.FALSE, Boolean.FALSE, true },
				{ ArtifactBindingMode.SUPPORTED, null, null, null, false },
				{ ArtifactBindingMode.SUPPORTED, null, Boolean.TRUE, Boolean.FALSE, true },
				{ ArtifactBindingMode.SUPPORTED, null, Boolean.FALSE, Boolean.TRUE, true },
				{ ArtifactBindingMode.SUPPORTED, null, Boolean.FALSE, Boolean.FALSE, false },
				{ ArtifactBindingMode.SUPPORTED, SamlBinding.ARTIFACT, Boolean.TRUE, Boolean.FALSE, true },
				{ ArtifactBindingMode.SUPPORTED, SamlBinding.ARTIFACT, Boolean.FALSE, Boolean.TRUE, true },
				{ ArtifactBindingMode.SUPPORTED, SamlBinding.ARTIFACT, Boolean.FALSE, Boolean.FALSE, true },
				{ ArtifactBindingMode.SUPPORTED, SamlBinding.POST, Boolean.TRUE, Boolean.FALSE, true },
				{ ArtifactBindingMode.SUPPORTED, SamlBinding.POST, Boolean.FALSE, Boolean.TRUE, true },
				{ ArtifactBindingMode.SUPPORTED, SamlBinding.POST, Boolean.FALSE, Boolean.FALSE, false },
				{ ArtifactBindingMode.SUPPORTED, SamlBinding.REDIRECT, null, null, false }
		};
	}

	@Test
	void assertionEncryptionReqTest() {
		String responseDestination = PERIMETER_URL;
		String rpid = "rpid";
		OidcProperties oidcConfig = givenMockedOidcProperties(responseDestination);

		assertFalse(relyingPartyService.assertionEncryptionReq(null, false, rpid));
		assertTrue(relyingPartyService.assertionEncryptionReq(SamlTestBase.dummyCredential(), false, rpid));
		assertFalse(relyingPartyService.assertionEncryptionReq(SamlTestBase.dummyCredential(), true, rpid));

		oidcConfig.setSamlEncrypt(true);
		assertTrue(relyingPartyService.assertionEncryptionReq(SamlTestBase.dummyCredential(), true, rpid));
	}

	private void mockSecurityChecks() {
		var secChecks = new SecurityChecks();
		secChecks.setDoSignSuccessResponse(false);
		secChecks.setDoSignFailureResponse(false);
		secChecks.setDoSignAssertions(false);
		doReturn(secChecks).when(trustBrokerProperties).getSecurity();
	}

	private OidcProperties givenMockedOidcProperties(String perimeterUrl) {
		OidcProperties oidcConfig = new OidcProperties();
		oidcConfig.setSamlEncrypt(false);
		oidcConfig.setPerimeterUrl(perimeterUrl);
		when(trustBrokerProperties.getOidc()).thenReturn(oidcConfig);
		return oidcConfig;
	}

	private static void expectedResult(Response authnResponse, String dataEncryAlg, String keyEncryAlg) {
		assertEquals(0, authnResponse.getAssertions().size());
		List<EncryptedAssertion> encryptedAssertions = authnResponse.getEncryptedAssertions();
		assertNotNull(encryptedAssertions);
		assertNotNull(encryptedAssertions.get(0));
		assertEquals(1, encryptedAssertions.size());
		assertNotNull(encryptedAssertions.get(0).getEncryptedData().getEncryptionMethod());
		assertEquals(dataEncryAlg, encryptedAssertions.get(0).getEncryptedData().getEncryptionMethod().getAlgorithm());
		assertNotNull(encryptedAssertions.get(0).getEncryptedKeys().get(0).getEncryptionMethod());
		assertEquals(keyEncryAlg, encryptedAssertions.get(0).getEncryptedKeys().get(0).getEncryptionMethod().getAlgorithm());
	}

	private RelyingParty givenRelyingPartyWithEncryption(String dataEncryAlg, String keyEncryAlg) {
		var encryption = Encryption.builder()
				.dataEncryptionAlgorithm(dataEncryAlg)
				.keyEncryptionAlgorithm(keyEncryAlg)
				.build();
		var saml = Saml.builder()
				.encryption(encryption)
				.build();
		return RelyingParty.builder()
				.rpEncryptionCred(SamlTestBase.dummyCredential())
				.id("Testid")
				.saml(saml)
				.build();
	}

	private RelyingParty givenMockedRelyingParty(boolean useArtifactBinding) {
		var relyingParty = RelyingParty.builder()
				.id(RP_ISSUER_ID)
				.build();
		if (useArtifactBinding) {
			relyingParty.setSaml(Saml.builder()
					.artifactBinding(ArtifactBinding.builder().outboundMode(ArtifactBindingMode.REQUIRED).build())
					.build());
			mockArtifactBinding();
		}
		doReturn(relyingParty).when(relyingPartySetupService).getRelyingPartyByIssuerIdOrReferrer(RP_ISSUER_ID, null);
		return relyingParty;
	}

	private static RelyingParty givenRelyingPartyWithEncryptionCred() {
		return RelyingParty.builder()
				.rpEncryptionCred(SamlTestBase.dummyCredential())
				.id(RP_ISSUER_ID)
				.build();
	}

	private ClaimsParty givenMockedClaimsParty() {
		var claimsParty = ClaimsParty.builder()
				.id(CP_ISSUER_ID)
				.build();
		doReturn(claimsParty).when(relyingPartySetupService).getClaimsProviderSetupByIssuerId(CP_ISSUER_ID, null);
		return claimsParty;
	}

	private Assertion givenAssertion() {
		Assertion assertion = OpenSamlUtil.buildAssertionObject();
		assertion.setIssueInstant(Instant.now());
		// ID
		assertion.setID(UUID.randomUUID().toString());
		// issuer
		assertion.setIssuer(OpenSamlUtil.buildSamlObject(Issuer.class));
		assertion.getIssuer().setValue("TEST_AUDIENCE");

		return assertion;
	}

	private Response givenResponseWithoutAssertion() {
		Response response = SamlFactory.createResponse(Response.class, trustBrokerProperties.getIssuer());
		response.setDestination("http://any.trustbroker.swiss");
		return response;
	}

	private AttributesSelection givenAttributesSelection() {
		List<Definition> definitions = new ArrayList<>();
		definitions.add(new Definition(CoreAttributeName.EMAIL));
		definitions.add(new Definition(CoreAttributeName.HOME_REALM));

		AttributesSelection attributesSelection = new AttributesSelection();
		attributesSelection.setDefinitions(definitions);

		return attributesSelection;
	}

	private StateData givenState(String rpIssuerId) {
		var spStateData = StateData.builder().id("spSessionId").issuer(rpIssuerId).build();
		return StateData.builder().id("sessionId").spStateData(spStateData).build();
	}

	private void assertContent(MockHttpServletResponse response, String expectedStatus, List<String> expectedContent)
			throws UnsupportedEncodingException {
		// the result is an HTML page with a form including the encoded SamlResponse and the RelayState
		// send form back to referrer (which is XML encoded)
		// the checks simple, they only have to handle what we produce, not generic HTML
		var encodedSloUrl = SLO_URL.replace(":", "&#x3a;").replace("/", "&#x2f;");
		var responseContent = response.getContentAsString();
		assertThat(responseContent, containsString("action=\"" + encodedSloUrl + '"'));
		for (var content : expectedContent) {
			assertThat(responseContent, containsString(content));
		}
		// response and relay state are encoded in a form fields
		var samlResponseField = "name=\"" + SamlIoUtil.SAML_RESPONSE_NAME + '"';
		assertThat(responseContent, containsString(samlResponseField));
		assertThat(responseContent, containsString("value=\"" + RELAY_STATE + '"'));
		var encodedResponse = responseContent.replace("\n", "").replaceAll("^.*" + samlResponseField + " value=\"",
				"").replaceAll("\".*$", "");
		var request = new MockHttpServletRequest();
		request.setMethod("POST");
		request.setParameter(SamlIoUtil.SAML_RESPONSE_NAME, encodedResponse);
		var messageContext = OpenSamlUtil.decodeSamlPostMessage(request);
		var logoutResponse = (LogoutResponse) messageContext.getMessage();
		assertThat(logoutResponse.getDestination(), is(SLO_URL));
		assertThat(logoutResponse.getStatus().getStatusCode().getValue(), is(expectedStatus));

		// cookie returned by mock must be set on response
		assertThat(response.getCookies(), is(not(nullValue())));
		assertThat(response.getCookies().length, is(1));
		assertThat(response.getCookies()[0].getName(), is(COOKIE_NAME));
		assertThat(response.getCookies()[0].getValue(), is(""));
	}

	private LogoutRequest setupMockData(MockHttpServletRequest request, boolean succeedLogout, boolean statePresent,
			ArtifactBindingMode mode) {
		// matching RPs
		var issuer = "myIssuer";
		var ssoGroup = "mySsoGroup";
		var ssoGroup2 = "mySsoGroup2";
		var sso = buildSso(ssoGroup);
		var sso2 = buildSso(ssoGroup2);
		// for invalid binding test:
		var artifactBinding = ArtifactBinding.builder().inboundMode(mode).build();
		var saml = Saml.builder().artifactBinding(artifactBinding).build();
		var secPol = SecurityPolicies.builder().requireSignedAuthnRequest(false).requireSignedResponse(false).build();
		var relyingParties = new ArrayList<RelyingParty>();
		var relyingPartySso = RelyingParty.builder().id("X-ENTERPRISE").sso(sso).saml(saml).securityPolicies(secPol).build();
		relyingParties.add(relyingPartySso);
		relyingParties.add(RelyingParty.builder().id("X-ENTERPRISE").sso(sso).saml(saml).securityPolicies(secPol).build());
		// simulate corner case if two SSO groups are matching
		var relyingPartySso2 = RelyingParty.builder().id("X-R").sso(sso2).saml(saml).securityPolicies(secPol).build();
		relyingParties.add(relyingPartySso2);
		doReturn(relyingParties).when(ssoService).getRelyingPartiesForSamlSlo(issuer, REFERRER);
		doReturn(SLO_URL).when(ssoService).computeSamlSingleLogoutUrl(eq(REFERRER), any());

		// states and cookies
		var sessionIndex = "mySessionIndex";
		var ssoSessionId = "mySsoSessionId";
		var spStateData = buildSpStateData();
		var ssoParticipants = Set.of(new SsoSessionParticipant(issuer, "cpIssuer", "acsUrl", null, null));
		var stateData = statePresent ? buildStateData(ssoGroup, sessionIndex, spStateData, ssoParticipants, ssoSessionId) : null;
		var stateData2 = statePresent ? buildStateData(ssoGroup2, sessionIndex, spStateData, ssoParticipants, null) : null;
		var cookie = new Cookie(COOKIE_NAME, "value");
		var expCookie = new Cookie(COOKIE_NAME, "");
		var cookie2 = new Cookie(COOKIE_NAME2, "value");
		var expCookie2 = new Cookie(COOKIE_NAME2, "");
		doAnswer(invocation -> {
			setCookiesToExpire(invocation.getArguments(), List.of(expCookie));
			return Optional.ofNullable(stateData);
		}).when(ssoService).logoutRelyingParty(issuer,
				List.of(sessionIndex), relyingPartySso, new Cookie[] { cookie, cookie2 },
				SsoService.SloState.builder().build());
		// validation and logout
		doReturn(Optional.ofNullable(stateData2)).when(ssoService).logoutRelyingParty(issuer,
				List.of(sessionIndex), relyingPartySso2, new Cookie[] { cookie, cookie2 },
				SsoService.SloState.builder().build());
		var logoutRequest = SamlFactory.createRequest(LogoutRequest.class, issuer);
		var sessionIndexObj = OpenSamlUtil.buildSamlObject(SessionIndex.class);
		sessionIndexObj.setValue(sessionIndex);
		logoutRequest.getSessionIndexes().add(sessionIndexObj);
		var nameId = SamlFactory.createNameId("name1@localhost", NameIDType.EMAIL, null);
		logoutRequest.setNameID(nameId);

		var notification = new SloNotification(new SloResponse());
		notification.setEncodedUrl(SLO_URL);
		doReturn(new SecurityChecks()).when(trustBrokerProperties).getSecurity();

		doReturn(Collections.emptyMap()).when(ssoService).buildSloVelocityParameters(relyingPartySso, REFERRER,
				ssoParticipants, nameId, null, null);

		request.setCookies(cookie, cookie2);
		request.addHeader(HttpHeaders.REFERER, REFERRER);
		return logoutRequest;
	}

	// allow position of argument SloState to change
	private static void setCookiesToExpire(Object[] arguments, List<Cookie> cookies) {
		if (arguments != null) {
			for (var argument : arguments) {
				if (argument instanceof SsoService.SloState sloState)
					sloState.setCookiesToExpire(cookies);
			}
		}
	}

	private static StateData buildSpStateData() {
		return StateData.builder().id("spSessionId").assertionConsumerServiceUrl("http://localhost/consumer").build();
	}

	private static Sso buildSso(String ssoGroup) {
		return Sso.builder().enabled(true).groupName(ssoGroup).sloUrl("http://localhost/logout").build();
	}

	private static StateData buildStateData(String ssoGroup, String sessionIndex, StateData spStateData,
			Set<SsoSessionParticipant> ssoParticipants, String ssoSessionId) {
		return StateData.builder()
				.id("mySessionId")
				.sessionIndex(sessionIndex)
				.spStateData(spStateData)
				.ssoState(SsoState.builder().ssoGroupName(ssoGroup).ssoParticipants(ssoParticipants).build())
				.ssoSessionId(ssoSessionId)
				.build();
	}

}