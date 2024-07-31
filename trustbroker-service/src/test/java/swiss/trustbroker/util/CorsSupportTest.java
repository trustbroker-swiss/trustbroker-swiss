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

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import swiss.trustbroker.config.dto.CorsPolicies;

class CorsSupportTest {

	public static final String URL = "https://example.trustbroker.swiss";

	@Test
	void testPreflight() {
		var origin = "http://auth-client:9090";
		var request = new MockHttpServletRequest();
		var response = new MockHttpServletResponse();
		request.setMethod(HttpMethod.OPTIONS.name());
		request.addHeader(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, HttpMethod.GET.name());
		request.addHeader(HttpHeaders.ORIGIN, origin);
		CorsSupport.setAccessControlHeaders(request, response, null);
		assertThat(response.getHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN), equalTo(origin));
		assertThat(response.getHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS), equalTo("true"));
		assertThat(response.getHeader(HttpHeaders.ACCESS_CONTROL_MAX_AGE), equalTo("3600"));
		assertThat(response.getHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS), equalTo(CorsSupport.DEFAULT_HEADERS));
		assertThat(response.getHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS), equalTo(CorsSupport.DEFAULT_METHODS));
	}

	@Test
	void testCorsOnOidcEndpoints() {
		var origin = "http://auth-client:9090";
		var request = new MockHttpServletRequest();
		var response = new MockHttpServletResponse();
		request.setMethod(HttpMethod.GET.name());
		request.setPathInfo("/oauth2");
		request.addHeader(HttpHeaders.ORIGIN, origin);
		CorsSupport.setAccessControlHeaders(request, response, CorsPolicies.builder()
				.allowedHeaders(List.of("ignored"))
				.allowedMethods(List.of("ignored"))
				.build());
		assertThat(response.getHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN), equalTo(origin));
		assertThat(response.getHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS), equalTo("true"));
		assertThat(response.getHeader(HttpHeaders.ACCESS_CONTROL_MAX_AGE), nullValue());
		assertThat(response.getHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS), nullValue());
		assertThat(response.getHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS), nullValue());
	}

	@ParameterizedTest
	@MethodSource
	void testGetAllowedOrigin(List<String> allowedOrigins, String origin, String referer, String expected) {
		var request = new MockHttpServletRequest();
		if (origin != null) {
			request.addHeader(HttpHeaders.ORIGIN, origin);
		}
		if (referer != null) {
			request.addHeader(HttpHeaders.REFERER, referer);
		}
		assertThat(CorsSupport.getAllowedOrigin(request, allowedOrigins), is(expected));

	}

	static Object[][] testGetAllowedOrigin() {
		return new Object[][] {
				{ null, null, null, null },
				{ Collections.emptyList(), URL, null, null },
				{ List.of("*"), URL, null, URL },
				{ List.of("http://localhost:8080", "*"), URL, null, URL },
				{ List.of(URL), URL, null, URL },
				{ List.of(URL + "/"), URL, null, URL },
				{ List.of(URL), null, URL + "/", URL },
				{ List.of(URL + "/"), null, URL + "/", URL }, // allowed match by referrer
				{ List.of("https://localhost", URL, "http://localhost:8443/logout"), URL, null, URL }
		};
	}


}