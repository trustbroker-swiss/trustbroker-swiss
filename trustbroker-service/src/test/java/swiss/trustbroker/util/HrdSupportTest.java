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

package swiss.trustbroker.util;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.util.ArrayList;
import java.util.List;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.mock.web.MockHttpServletRequest;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.NetworkConfig;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderRelyingParty;
import swiss.trustbroker.homerealmdiscovery.service.NoOpHrdService;
import swiss.trustbroker.oidc.session.HttpExchangeSupport;

@SpringBootTest(classes = WebSupport.class)
class HrdSupportTest {

	private static final String CP_PUBLIC_ID = "urn:test:TESTCP";

	private static final String CP_BROKER_ID = "urn:test:BROKER";

	private static final String CP_ENTERPRISE_ID = "urn:test:ENTERPRISE";

	private static final String CP_MOBILE_ID = "https://test-mobile.trustbroker.swiss";

	private static final String GW_MOBILE_IP_REGEX = "192[.]168[.]11[.][0-9]+";

	private static final String AUTOLOGIN_COOKIE = "TEST_autoLogin";

	@SpyBean
	private NoOpHrdService hrdService;

	@Test
	void testClaimsProviderHintUrlTesterHeader() {
		var request = new MockHttpServletRequest();
		var properties = givenProperties();
		request.addHeader(HrdSupport.HTTP_URLTESTER_CP, CP_PUBLIC_ID);
		assertThat(HrdSupport.getClaimsProviderHint(request, properties), is(CP_PUBLIC_ID));
	}

	@Test
	void testClaimsProviderHintUrlTesterCookie() {
		var request = new MockHttpServletRequest();
		var properties = givenProperties();
		var cookie = new Cookie(HrdSupport.HTTP_URLTESTER_CP, CP_PUBLIC_ID);
		request.setCookies(cookie);
		assertThat(HrdSupport.getClaimsProviderHint(request, properties), is(CP_PUBLIC_ID));
	}

	@ParameterizedTest
	@MethodSource
	void testClaimsProviderHintMobileGw(String ip, String cpMobileId) {
		var request = new MockHttpServletRequest();
		var properties = givenProperties();
		request.addHeader(WebSupport.HTTP_HEADER_X_FORWARDED_FOR, ip);
		assertThat(HrdSupport.getClaimsProviderHint(request, properties), is(cpMobileId));
	}

	static String[][] testClaimsProviderHintMobileGw() {
		return new String[][] {
				{ "192.168.11.55", CP_MOBILE_ID },
				{ "192.168.11.1", CP_MOBILE_ID },
				{ "127.0.0.1, 192.168.0.0, 192.168.11.55", CP_MOBILE_ID },
				{ "127.0.0.1, 192.168.11.55, 192.168.0.0", CP_MOBILE_ID },
				{ "192.168.12.55", null },
				{ "127.0.0.1, 192.168.0.0, 192.168.10.55", null },
		};
	}

	@Test
	void testReduceClaimsProviderMappings() {
		var request = new MockHttpServletRequest();
		var mappings = givenClaimsProviderMappings();
		var reduced = HrdSupport.reduceClaimsProviderMappings(request, "MISS", null, CP_MOBILE_ID, mappings, givenProperties(),
				hrdService);
		assertThat(reduced.size(), equalTo(1)); // all CPs are returned
	}

	@Test
	void testClaimsProviderHintEnterpriseIdp() {
		var request = new MockHttpServletRequest();
		var properties = givenProperties();
		request.addParameter(HrdSupport.HTTP_CP_HINT, "enterprise");
		assertThat(HrdSupport.getClaimsProviderHint(request, properties), is(CP_ENTERPRISE_ID));
	}


	@Test
	void testClaimsProviderHintLnClientNetworkInternet() {
		var request = new MockHttpServletRequest();
		var properties = givenProperties();
		request.addHeader(properties.getNetwork().getNetworkHeader(), properties.getNetwork().getInternetNetworkName());
		HttpExchangeSupport.begin(request, null); // OIDC side only
		assertThat(HrdSupport.getClaimsProviderHint(properties), is(CP_PUBLIC_ID));
	}

	@Test
	void testClaimsProviderHintLnClientNetworkIntranet() {
		var request = new MockHttpServletRequest();
		var properties = givenProperties();
		request.addHeader(properties.getNetwork().getNetworkHeader(), properties.getNetwork().getIntranetNetworkName());
		HttpExchangeSupport.begin(request, null); // OIDC side only
		assertThat(HrdSupport.getClaimsProviderHint(properties), is(CP_ENTERPRISE_ID));
	}

	@Test
	void testReduceClaimsProviderMappingsByRpIssuerId() {
		var request = new MockHttpServletRequest();
		var mappings = givenClaimsProviderMappings();
		var expectedCp = "CP1";
		var reduced = HrdSupport.reduceClaimsProviderMappings(request, "RP1", null, null, mappings, givenProperties(), hrdService);
		assertThat(reduced.size(), equalTo(1));
		assertThat(reduced.get(0).getId(), equalTo(expectedCp));
	}

	@Test
	void testReduceClaimsProviderMappingsByHint() {
		var request = new MockHttpServletRequest();
		var mappings = givenClaimsProviderMappings();
		var expectedCp = "CP2";
		var reduced = HrdSupport.reduceClaimsProviderMappings(request, "RP1", null, expectedCp, mappings, givenProperties(), hrdService);
		assertThat(reduced.size(), equalTo(1));
		assertThat(reduced.get(0).getId(), equalTo(expectedCp));
	}

	@Test
	void testReduceClaimsProviderMappingsByProviderName() {
		var request = new MockHttpServletRequest();
		var mappings = givenClaimsProviderMappings();
		var expectedCp = "CP2";
		var reduced = HrdSupport.reduceClaimsProviderMappings(request, "RP1", "RP2", null, mappings, givenProperties(), hrdService);
		assertThat(reduced.size(), equalTo(1));
		assertThat(reduced.get(0).getId(), equalTo(expectedCp));
	}

	@Test
	void testReduceClaimsProviderMappingsNotMatchingAnything() {
		var request = new MockHttpServletRequest();
		var mappings = givenClaimsProviderMappings();
		var reduced = HrdSupport.reduceClaimsProviderMappings(request, "MISS", null, null, mappings, givenProperties(), hrdService);
		assertThat(reduced.size(), equalTo(2)); // all CPs matched
	}

	private static List<ClaimsProviderRelyingParty> givenClaimsProviderMappings() {
		var ret = new ArrayList<ClaimsProviderRelyingParty>();
		for (int count = 0; count < 5; count++) {
			ret.add(ClaimsProviderRelyingParty.builder()
					.id("CP" + count)
					.clientNetworks("INTRANET,INTERNET")
					.relyingPartyAlias("RP" + count)
					.build());
		}
		// no aliases, so HRD screen should show these 2
		ret.add(ClaimsProviderRelyingParty.builder()
				.id(CP_ENTERPRISE_ID)
				.clientNetworks("INTRANET")
				.build());
		ret.add(ClaimsProviderRelyingParty.builder()
				.id(CP_PUBLIC_ID)
				.clientNetworks("INTERNET")
				.build());
		// gateway IP overrides everything else so '*' leads to just eliminate it from HRD screen because it's not working anyway
		ret.add(ClaimsProviderRelyingParty.builder()
				.id(CP_MOBILE_ID)
				.clientNetworks("INTRANET,INTERNET")
				.relyingPartyAlias("RP-ID-123-UNUSED")
				.build());
		return ret;
	}

	private static TrustBrokerProperties givenProperties() {
		var ret = new TrustBrokerProperties();
		ret.setPublicIdpId(CP_PUBLIC_ID);
		ret.setBrokerIdpId(CP_BROKER_ID);
		ret.setEnterpriseIdpId(CP_ENTERPRISE_ID);
		ret.setMobileIdpId(CP_MOBILE_ID);
		ret.setPublicAutoLoginCookie(AUTOLOGIN_COOKIE);
		var network = new NetworkConfig();
		ret.setNetwork(network);
		network.setMobileGatewayIpRegex(GW_MOBILE_IP_REGEX);
		return ret;
	}

}
