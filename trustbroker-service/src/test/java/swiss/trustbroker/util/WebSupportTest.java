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

import jakarta.servlet.http.Cookie;
import net.shibboleth.shared.net.URLBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.servlet.view.UrlBasedViewResolver;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.tracing.TraceSupport;
import swiss.trustbroker.config.dto.NetworkConfig;

@SpringBootTest(classes = WebSupport.class)
class WebSupportTest {

	private static final String TEST_URL = "https://localhost";

	private static final String TEST_QUERY = "one=uno&two=due&three=tre&two=deux";

	private static final String TEST_URL_WITH_QUERY = TEST_URL + '?' + TEST_QUERY;


	@Test
	void getUniqueQueryParameter() throws Exception {
		var urlBuilder = new URLBuilder(TEST_URL_WITH_QUERY);
		assertThat(WebSupport.getUniqueQueryParameter(urlBuilder, "one"), is("uno"));
		assertThrows(RequestDeniedException.class, () -> WebSupport.getUniqueQueryParameter(urlBuilder, "two"));
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
		var result = WebSupport.getViewRedirectResponse(null); // NOSONAR
		assertThat(result, is(nullValue()));
	}

	@Test
	void testGetHttpContext() {
		var request = new MockHttpServletRequest();
		var network = new NetworkConfig();

		assertEquals(0, WebSupport.getHttpContext(request, network).size());

		request.setParameter("username", "test");
		assertEquals(1, WebSupport.getHttpContext(request, network).size());

		request.addHeader(TraceSupport.XTB_CLIENTIP, "test");
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
	void canaryModeEnabledTest() {
		var request = new MockHttpServletRequest();

		var noConfig = NetworkConfig.builder()
									.build();
		assertFalse(WebSupport.canaryModeEnabled(request, noConfig));

		var networkConfig = NetworkConfig.builder()
										 .canaryMarkerName("canary")
										 .canaryEnabledValue("always")
										 .build();
		request.addHeader(networkConfig.getCanaryMarkerName(), networkConfig.getCanaryEnabledValue());
		assertTrue(WebSupport.canaryModeEnabled(request, networkConfig));

		request.removeHeader(networkConfig.getCanaryMarkerName());
		request.setCookies(new Cookie(networkConfig.getCanaryMarkerName(), networkConfig.getCanaryEnabledValue()));
		assertTrue(WebSupport.canaryModeEnabled(request, networkConfig));
	}

}
