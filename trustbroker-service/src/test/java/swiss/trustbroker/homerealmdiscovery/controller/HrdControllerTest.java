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

package swiss.trustbroker.homerealmdiscovery.controller;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Optional;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import swiss.trustbroker.api.announcements.service.AnnouncementService;
import swiss.trustbroker.api.profileselection.dto.ProfileData;
import swiss.trustbroker.api.profileselection.dto.ProfileResponse;
import swiss.trustbroker.api.profileselection.service.ProfileSelectionService;
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.SecurityChecks;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderRelyingParty;
import swiss.trustbroker.federation.xmlconfig.Flow;
import swiss.trustbroker.federation.xmlconfig.FlowPolicies;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.homerealmdiscovery.dto.ProfileRequest;
import swiss.trustbroker.homerealmdiscovery.dto.SupportInfo;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.saml.dto.DeviceInfoReq;
import swiss.trustbroker.saml.dto.RpRequest;
import swiss.trustbroker.saml.dto.UiObject;
import swiss.trustbroker.saml.service.AssertionConsumerService;
import swiss.trustbroker.saml.service.ClaimsProviderService;
import swiss.trustbroker.saml.service.RelyingPartyService;
import swiss.trustbroker.saml.service.SamlOutputService;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.sessioncache.service.StateCacheService;
import swiss.trustbroker.sso.service.SsoService;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.SamlValidator;
import swiss.trustbroker.util.WebSupport;

@ExtendWith(SpringExtension.class)
@WebMvcTest
@ContextConfiguration(classes = {
		HrdController.class
})
@AutoConfigureMockMvc
class HrdControllerTest {

	private static final String SESSION_ID = "relay1";

	private static final String SSO_SESSION_ID = "sso1";

	private static final String AUTHN_REQUEST_ID = "issuerReq1";

	private static final String RP_ISSUER_ID = "rp1";

	private static final String CP_ISSUER_ID = "cp1";

	private static final String DEVICE_ID = "devId1";

	private static final String URL = "https://localhost";

	private static final String PROFILE_ID = "id1";

	@MockBean
	TrustBrokerProperties trustBrokerProperties;

	@MockBean
	SamlValidator samlValidator;

	@MockBean
	private AssertionConsumerService assertionConsumerService;

	@MockBean
	private RelyingPartyService relyingPartyService;

	@MockBean
	private RelyingPartySetupService relyingPartySetupService;

	@MockBean
	private ClaimsProviderService claimsProviderService;

	@MockBean
	private SsoService ssoService;

	@MockBean
	private AnnouncementService announcementService;

	@MockBean
	private ProfileSelectionService profileSelectionService;

	@MockBean
	private StateCacheService stateCacheService;

	@MockBean
	private SamlOutputService samlOutputService;

	@Autowired
	private WebApplicationContext webApplicationContext;

	@SpyBean
	private ApiSupport apiSupport;

	private MockMvc mockMvc;

	@BeforeEach
	public void setup() {
		SamlInitializer.initSamlSubSystem();
		this.mockMvc = MockMvcBuilders.webAppContextSetup(this.webApplicationContext).build();
		this.apiSupport = new ApiSupport(trustBrokerProperties);
	}

	@Test
	void getHrdTilesForRpIssuer() throws Exception {
		var result = RpRequest.builder().uiObjects(List.of(UiObject.builder().urn(CP_ISSUER_ID).build())).build();
		var expectedJson = new ObjectMapper().writeValueAsString(result.getUiObjects());
		doReturn(result).when(assertionConsumerService).renderUI(eq(RP_ISSUER_ID), eq(URL), any(), any(), eq(null), eq(null));
		this.mockMvc.perform(get(apiSupport.getHrdRpApi(RP_ISSUER_ID))
						.header(HttpHeaders.REFERER, URL))
				.andExpect(status().isOk())
				.andExpect(content().json(expectedJson));
	}

	@Test
	void handleCheckDeviceInfoNoSsoSingleCp() throws Exception {
		var cpRp = ClaimsProviderRelyingParty.builder().build();
		var stateDataByAuthnReq = buildStateByAuthnReq();
		handleCheckDeviceInfo(List.of(cpRp), Optional.empty(), stateDataByAuthnReq, false, null, null);
		verify(stateCacheService).save(stateDataByAuthnReq, HrdController.class.getSimpleName());
		verify(claimsProviderService).sendSamlToCp(any(), any(), any(), eq(stateDataByAuthnReq), eq(CP_ISSUER_ID));
	}

	@Test
	void handleCheckDeviceInfoNoSsoMultipleCp() throws Exception {
		var cpRp = ClaimsProviderRelyingParty.builder().build();
		// just more than one ClaimsProviderRelyingParty
		var stateDataByAuthnReq = buildStateByAuthnReq();
		handleCheckDeviceInfo(List.of(cpRp, cpRp), Optional.empty(), stateDataByAuthnReq, false, null, null);
		verify(stateCacheService, never()).save(stateDataByAuthnReq, "Test");
	}

	@Test
	void handleCheckDeviceInfoInvalidSsoStateSingleCp() throws Exception {
		var cpRp = ClaimsProviderRelyingParty.builder().build();
		var stateDataByAuthnReq = buildStateByAuthnReq();
		var ssoStateData = buildSsoState();
		handleCheckDeviceInfo(List.of(cpRp), Optional.of(ssoStateData), stateDataByAuthnReq, false, null, null);
		// no SSO established, device info not set
		assertThat(ssoStateData.getDeviceId(), is(nullValue()));
		verify(stateCacheService, never()).save(ssoStateData, "Test");
		verify(claimsProviderService).sendSamlToCp(any(), any(), any(), eq(stateDataByAuthnReq), eq(CP_ISSUER_ID));
	}

	@Test
	void handleCheckDeviceInfoValidSsoStateSingleNoAccessRequestNoProfile() throws Exception {
		var cpRp = ClaimsProviderRelyingParty.builder().build();
		var stateDataByAuthnReq = buildStateByAuthnReq();
		var ssoStateData = buildSsoState();
		handleCheckDeviceInfo(List.of(cpRp), Optional.of(ssoStateData), stateDataByAuthnReq, true, null, null);
		verify(stateCacheService, never()).save(stateDataByAuthnReq, "Test");
		verifyNoInteractions(claimsProviderService);
		verify(relyingPartyService).sendAuthnResponseToRpFromState(any(), any(), any(),
				eq(ssoStateData), eq(stateDataByAuthnReq));
	}

	@Test
	void handleCheckDeviceInfoValidSsoStateSingleAccessRequest() throws Exception {
		var arRedirect = apiSupport.getAccessRequestInitiateApi(AUTHN_REQUEST_ID);
		var cpRp = ClaimsProviderRelyingParty.builder().build();
		var ssoStateData = buildSsoState();
		var stateDataByAuthnReq = buildStateByAuthnReq();
		handleCheckDeviceInfo(List.of(cpRp), Optional.of(ssoStateData), stateDataByAuthnReq, true, arRedirect, null);
		verify(stateCacheService, never()).save(stateDataByAuthnReq, "Test");
		verifyNoInteractions(claimsProviderService);
		verify(relyingPartyService).performAccessRequestIfRequired(any(), eq(buildRp()), eq(ssoStateData),
				eq(stateDataByAuthnReq));
	}

	@Test
	void handleCheckDeviceInfoValidSsoStateSingleProfileSelection() throws Exception {
		var profileRedirect = apiSupport.getProfileSelectionUrl(SSO_SESSION_ID);
		var cpRp = ClaimsProviderRelyingParty.builder().build();
		var ssoStateData = buildSsoState();
		var stateDataByAuthnReq = buildStateByAuthnReq();
		handleCheckDeviceInfo(List.of(cpRp), Optional.of(ssoStateData), stateDataByAuthnReq, true, null,
				profileRedirect);
		verify(stateCacheService, never()).save(stateDataByAuthnReq, "Test");
		verifyNoInteractions(claimsProviderService);
		verify(relyingPartyService).sendAuthnResponseToRpFromState(any(), any(), any(),
				eq(ssoStateData), eq(stateDataByAuthnReq));
	}


	private void handleCheckDeviceInfo(List<ClaimsProviderRelyingParty> cpRpList, Optional<StateData> ssoStateData,
			StateData stateDataByAuthnReq, boolean ssoStateValid, String accessRequestRedirect, String profileSelectionRedirect)
			throws Exception {
		var rp = buildRp();
		var cp = buildCp();
		mockLookups(rp, cp, ssoStateData, stateDataByAuthnReq, ssoStateValid);
		var cookies = buildCookies();
		doReturn(ssoStateData).when(ssoService).findValidStateFromCookies(rp, cp, cookies);
		doReturn(Optional.of(stateDataByAuthnReq)).when(stateCacheService).findBySpId(AUTHN_REQUEST_ID,
				HrdController.class.getSimpleName());
		if (ssoStateData.isPresent()) {
			doReturn(accessRequestRedirect).when(relyingPartyService)
					.performAccessRequestIfRequired(any(), eq(rp), eq(ssoStateData.get()), eq(stateDataByAuthnReq));
			doReturn(profileSelectionRedirect).when(relyingPartyService).sendAuthnResponseToRpFromState(
					any(), any(), any(), eq(ssoStateData.get()),
					eq(stateDataByAuthnReq));
		}
		var rpRequest = RpRequest.builder().claimsProviders(cpRpList).build();
		doReturn(rpRequest).when(assertionConsumerService).getRpRequestDetails(eq(RP_ISSUER_ID), eq(URL), any(), any(),
				eq(null), eq(stateDataByAuthnReq));
		var json = buildDeviceInfoJsonString();
		var resultRedirect = accessRequestRedirect != null ? accessRequestRedirect : (
				profileSelectionRedirect != null ? profileSelectionRedirect : null);
		var resultJson = resultRedirect != null ? buildProfileJsonString(resultRedirect) : null;
		this.mockMvc.perform(post(apiSupport.getDeviceInfoApi())
						.header(WebSupport.HTTP_HEADER_DEVICE_ID, DEVICE_ID)
						.contentType(MediaType.APPLICATION_JSON_VALUE)
						.content(json)
						.cookie(cookies))
				.andExpect(status().isOk())
				.andExpect(resultJson != null ? content().json(resultJson) : content().string(""));
	}

	@Test
	void handleRedirectToClaimsProviderSsoJoin() throws Exception {
		var stateByAuthnReq = buildStateByAuthnReq();
		var rp = buildRp();
		mockLookups(rp, null, Optional.empty(), stateByAuthnReq, false);
		var ssoOperation = SsoService.SsoSessionOperation.JOIN;
		var cookies = buildCookies();
		doReturn(ssoOperation).when(ssoService).prepareRedirectForDeviceInfoAfterHrd(cookies, stateByAuthnReq, CP_ISSUER_ID);
		var redirectForDeviceInfo = apiSupport.getDeviceInfoUrl(CP_ISSUER_ID, RP_ISSUER_ID, AUTHN_REQUEST_ID);
		this.mockMvc.perform(get(apiSupport.getHrdCpApi(CP_ISSUER_ID, AUTHN_REQUEST_ID)).cookie(cookies))
				.andExpect(status().isOk())
				.andExpect(header().string(HttpHeaders.LOCATION, redirectForDeviceInfo));
		verifyNoInteractions(claimsProviderService);
	}

	@Test
	void handleRedirectToClaimsProviderNoSso() throws Exception {
		var stateByAuthnReq = buildStateByAuthnReq();
		var rp = buildRp();
		mockLookups(rp, null, Optional.empty(), stateByAuthnReq, false);
		var ssoOperation = SsoService.SsoSessionOperation.IGNORE;
		var cookies = buildCookies();
		doReturn(ssoOperation).when(ssoService).prepareRedirectForDeviceInfoAfterHrd(cookies, stateByAuthnReq, CP_ISSUER_ID);
		var redirectForDeviceInfo = apiSupport.getDeviceInfoUrl(CP_ISSUER_ID, RP_ISSUER_ID, AUTHN_REQUEST_ID);
		this.mockMvc.perform(get(apiSupport.getHrdCpApi(CP_ISSUER_ID, AUTHN_REQUEST_ID)).cookie(cookies))
				.andExpect(status().isOk())
				.andExpect(header().doesNotExist(HttpHeaders.LOCATION));
		verify(claimsProviderService).sendSamlToCpWithMandatoryIds(any(), any(), any(), eq(stateByAuthnReq), eq(CP_ISSUER_ID));
	}

	@Test
	void handleContinueToRp() throws Exception {
		var stateByAuthnReq = buildStateByAuthnReq();
		var rp = buildRp();
		doReturn(stateByAuthnReq).when(stateCacheService)
				.findMandatoryValidState(AUTHN_REQUEST_ID, HrdController.class.getSimpleName());
		mockLookups(rp, null, Optional.empty(), stateByAuthnReq, false);
		doReturn(true).when(trustBrokerProperties).isSecureBrowserHeaders();
		var cookies = buildCookies();
		this.mockMvc.perform(get(apiSupport.getHrdRpContinueApi(AUTHN_REQUEST_ID)).cookie(cookies))
				.andExpect(status().isOk())
				.andExpect(header().doesNotExist(HttpHeaders.LOCATION));
		verify(relyingPartyService).sendResponseToRpFromSessionState(any(), any(), any(), any(), any());
	}

	@Test
	void handleProfiles() throws Exception {
		var result = ProfileResponse.builder().redirectUrl(URL).id(PROFILE_ID).build();
		var resultJson = new ObjectMapper().writeValueAsString(result);
		var stateData = StateData.builder().id(PROFILE_ID).build();
		var cpResponse = CpResponse.builder().build();
		stateData.setCpResponse(cpResponse);
		doReturn(stateData).when(stateCacheService).find(PROFILE_ID, HrdController.class.getSimpleName());
		doReturn(result).when(profileSelectionService).buildProfileResponse(
				ProfileData.builder().profileId(PROFILE_ID).build(), stateData.getCpResponse());
		this.mockMvc.perform(get(apiSupport.getProfilesApi()).header(WebSupport.HTTP_HEADER_XTB_PROFILE_ID, PROFILE_ID))
				.andExpect(status().isOk())
				.andExpect(content().json(resultJson));
	}

	@Test
	void handleSelectProfile() throws Exception {
		this.mockMvc.perform(postSelectedProfile(null))
			.andExpect(status().isOk());
	}

	@Test
	void handleSelectProfileWithRedirect() throws Exception {
		this.mockMvc.perform(postSelectedProfile(URL))
			.andExpect(status().is3xxRedirection())
			.andExpect(header().string(HttpHeaders.LOCATION, URL));
	}

	private RequestBuilder postSelectedProfile(String redirectUrl) throws JsonProcessingException {
		var request = new ProfileRequest(PROFILE_ID, SESSION_ID);
		var requestJson = new ObjectMapper().writeValueAsString(request);
		doReturn(redirectUrl).when(relyingPartyService)
							 .sendResponseWithSelectedProfile(eq(samlOutputService), eq(request), any(), any());
		return post(apiSupport.getProfileApi())
				.content(requestJson)
				.contentType(MediaType.APPLICATION_JSON_VALUE);
	}

	@Test
	void handleContinueToHrd() throws Exception {
		var stateByAuthnReq = buildStateByAuthnReq();
		var rp = buildRp();
		mockLookups(rp, null, Optional.empty(), stateByAuthnReq, false);
		doReturn(stateByAuthnReq).when(stateCacheService)
				.find(stateByAuthnReq.getId(), HrdController.class.getSimpleName());
		this.mockMvc.perform(get(apiSupport.getContinueToHrdApi(stateByAuthnReq.getId())))
				.andExpect(status().is3xxRedirection())
				.andExpect(header().string(HttpHeaders.LOCATION, apiSupport.getHrdUrl(RP_ISSUER_ID, AUTHN_REQUEST_ID)));
	}

	@Test
	void handleFetchSupportInfo() throws Exception {
		var errorCode = "pwresetfailed";
		var stateByAuthnReq = buildStateByAuthnReq();
		var rp = buildRp();
		var phone = "12345";
		var email = "test@trustbroker.swiss";
		var flows = List.of(
				Flow.builder().id("UnknownPrincipal").appUrl("dummy").build(),
				Flow.builder().id("PwResetFailed").supportPhone(phone).supportEmail(email).appUrl(URL).build()
		);
		rp.setFlowPolicies(FlowPolicies.builder().flows(flows).build());
		mockLookups(rp, null, Optional.empty(), stateByAuthnReq, false);
		doReturn(Optional.of(stateByAuthnReq)).when(stateCacheService)
				.findOptional(stateByAuthnReq.getId(), HrdController.class.getSimpleName());
		doReturn(rp).when(relyingPartySetupService).getRelyingPartyByIssuerIdOrReferrer(RP_ISSUER_ID,
				stateByAuthnReq.getRpReferer(), true);
		var result = SupportInfo.builder().appUrl(URL).phoneNumber(phone).emailAddress(email).build();
		var resultJson = new ObjectMapper().writeValueAsString(result);
		this.mockMvc.perform(get(apiSupport.getSupportInfoApi(errorCode, stateByAuthnReq.getId())))
				.andExpect(status().isOk())
				.andExpect(content().json(resultJson));
	}

	private void mockLookups(RelyingParty rp, ClaimsParty cp, Optional<StateData> ssoState, StateData stateDataByAuthnReq,
			boolean ssoStateValid) {
		doReturn(Optional.of(stateDataByAuthnReq)).when(stateCacheService).findBySpId(AUTHN_REQUEST_ID,
				HrdController.class.getSimpleName());
		doReturn(rp).when(relyingPartySetupService).getRelyingPartyByIssuerIdOrReferrer(RP_ISSUER_ID, null);
		if (cp != null) {
			doReturn(cp).when(relyingPartySetupService).getClaimsProviderSetupByIssuerId(CP_ISSUER_ID, null);
			if (ssoState.isPresent()) {
				doReturn(ssoStateValid).when(ssoService).ssoStateValidForDeviceInfo(
						cp, rp, ssoState.get(), stateDataByAuthnReq, DEVICE_ID, CP_ISSUER_ID);
			}
		}

		var sec = new SecurityChecks();
		doReturn(sec).when(trustBrokerProperties).getSecurity();
	}

	private static StateData buildStateByAuthnReq() {
		var spStateData = StateData.builder()
				.id(AUTHN_REQUEST_ID)
				.issuer(RP_ISSUER_ID)
				.referer(URL)
				.build();
		var stateData = StateData.builder()
				.id(SESSION_ID)
				.issuer(CP_ISSUER_ID)
				.spStateData(spStateData)
				.build();
		return stateData;
	}

	private static StateData buildSsoState() {
		var ssoStateData = StateData.builder().id(SSO_SESSION_ID).build();
		return ssoStateData;
	}

	private static RelyingParty buildRp() {
		var rp = RelyingParty.builder().id(RP_ISSUER_ID).build();
		return rp;
	}

	private static ClaimsParty buildCp() {
		var cp = ClaimsParty.builder().id(CP_ISSUER_ID).build();
		return cp;
	}

	private static Cookie[] buildCookies() {
		return new Cookie[] { new Cookie("name", "value") };
	}

	private static String buildDeviceInfoJsonString() throws JsonProcessingException {
		var deviceInfo = new DeviceInfoReq();
		deviceInfo.setId(AUTHN_REQUEST_ID);
		deviceInfo.setCpUrn(ApiSupport.encodeUrlParameter(CP_ISSUER_ID));
		deviceInfo.setRpUrn(ApiSupport.encodeUrlParameter(RP_ISSUER_ID));
		var json = new ObjectMapper().writeValueAsString(deviceInfo);
		return json;
	}

	private String buildProfileJsonString(String redirectUrl) throws JsonProcessingException {
		var url = apiSupport.relativeUrl(redirectUrl);
		var profileResponse = ProfileResponse.builder().redirectUrl(url).build();
		return new ObjectMapper().writeValueAsString(profileResponse);
	}

}
