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
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import jakarta.servlet.http.Cookie;
import net.shibboleth.shared.net.URLBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.servlet.view.UrlBasedViewResolver;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.config.dto.NetworkConfig;

@SpringBootTest(classes = WebSupport.class)
class WebSupportTest {

	private static final String TEST_URL = "https://localhost";

	private static final String TEST_QUERY = "one=uno&two=due&three=tre&two=deux";

	private static final String TEST_URL_WITH_QUERY = TEST_URL + '?' + TEST_QUERY ;


	@Test
	void getUniqueQueryParameter() throws Exception {
		var urlBuilder = new URLBuilder(TEST_URL_WITH_QUERY);
		assertThat(WebSupport.getUniqueQueryParameter(urlBuilder, "one"), is("uno"));
		assertThrows(RequestDeniedException.class,() -> WebSupport.getUniqueQueryParameter(urlBuilder, "two"));
		assertThat(WebSupport.getUniqueQueryParameter(urlBuilder, "four"), is(nullValue()));
	}

	@Test
	void getViewRedirectResponse() {
		var url = "test";
		var result = WebSupport.getViewRedirectResponse(url);
		assertThat(result, is(UrlBasedViewResolver.REDIRECT_URL_PREFIX + url));
	}

	@Test
	void getViewRedirectResponseNull() {
		var result = WebSupport.getViewRedirectResponse( null); // NOSONAR
		assertThat(result, is(nullValue()));
	}

	@Test
	void testGetHttpContext(){
		var request = new MockHttpServletRequest();
		var network = new NetworkConfig();

		assertEquals(0, WebSupport.getHttpContext(request, network).size());

		request.setParameter("username", "test");
		assertEquals(1, WebSupport.getHttpContext(request, network).size());

		request.addHeader(WebSupport.XTB_MDC_CLIENT_IP, "test");
		assertEquals(1, WebSupport.getHttpContext(request, network).size());

		request.addHeader(network.getNetworkHeader(), "test");
		assertEquals(2, WebSupport.getHttpContext(request, network).size());
	}

	@Test
	void testClientNetworkInjectionOnIntranet() {
		var network = new NetworkConfig();

		// no network injection
		var request = new MockHttpServletRequest();
		assertThat(WebSupport.getClientNetworkOnIntranet(request, network), is(nullValue()));

		// intranet access, no injection
		request = new MockHttpServletRequest();
		request.addHeader(network.getNetworkHeader(), network.getIntranetNetworkName());
		assertThat(WebSupport.getClientNetworkOnIntranet(request, network), is(network.getIntranetNetworkName()));

		// internet access, injection ignored
		request = new MockHttpServletRequest();
		request.addHeader(network.getNetworkHeader(), network.getInternetNetworkName());
		request.addHeader(network.getTestNetworkHeader(), network.getIntranetNetworkName());
		assertThat(WebSupport.getClientNetworkOnIntranet(request, network), is(network.getInternetNetworkName()));

		// intranet access, injection working
		request = new MockHttpServletRequest();
		request.addHeader(network.getNetworkHeader(), network.getIntranetNetworkName());
		request.addHeader(network.getTestNetworkHeader(), network.getInternetNetworkName());
		assertThat(WebSupport.getClientNetworkOnIntranet(request, network), is(network.getInternetNetworkName()));
	}

	@Test
	void testClientIp() {
		var singleIp = new MockHttpServletRequest();
		singleIp.addHeader(WebSupport.HTTP_HEADER_X_ORIGINAL_FORWARDED_FOR, "10.0.0.1");
		assertThat(WebSupport.getClientIp(singleIp), is("10.0.0.1/XOFF"));

		var proxyIps = new MockHttpServletRequest();
		proxyIps.addHeader(WebSupport.HTTP_HEADER_X_ORIGINAL_FORWARDED_FOR, "10.0.0.1, 10.0.0.2");
		assertThat(WebSupport.getClientIp(proxyIps, false), is("10.0.0.1"));

		var gatewayIp = new MockHttpServletRequest();
		gatewayIp.addHeader(WebSupport.HTTP_HEADER_X_ORIGINAL_FORWARDED_FOR, "10.0.0.1, 10.0.0.2");
		assertThat(WebSupport.getGatewayIp(gatewayIp), is("10.0.0.2"));
		assertThat(WebSupport.getGatewayIps(gatewayIp), is(List.of("10.0.0.1", "10.0.0.2").toArray()));
		// override with simulation
		gatewayIp.addHeader(WebSupport.HTTP_HEADER_X_SIMULATED_FORWARDED_FOR, "10.0.0.3");
		assertThat(WebSupport.getGatewayIps(gatewayIp), is(List.of("10.0.0.3").toArray()));
		assertThat(WebSupport.getClientIps(gatewayIp, false), is(List.of("10.0.0.1", "10.0.0.2").toArray()));

		var noIp = new MockHttpServletRequest();
		assertThat(WebSupport.getGatewayIp(noIp), is("127.0.0.1"));
		assertThat(WebSupport.getClientIp(noIp), is("127.0.0.1/SRA"));
	}

	@Test
	void canaryModeEnabledTest() {
		var request = new MockHttpServletRequest();

		assertFalse(WebSupport.canaryModeEnabled(request));

		request.addHeader(WebSupport.HTTP_CANARY_MARKER, WebSupport.HTTP_CANARY_MARKER_ALWAYS);
		assertTrue(WebSupport.canaryModeEnabled(request));

		request.removeHeader(WebSupport.HTTP_CANARY_MARKER);
		request.setCookies(new Cookie(WebSupport.HTTP_CANARY_MARKER, WebSupport.HTTP_CANARY_MARKER_ALWAYS));
		assertTrue(WebSupport.canaryModeEnabled(request));

	}

}
