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

package swiss.trustbroker.federation.xmlconfig;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class AcWhitelistTest {

	@ParameterizedTest
	@MethodSource
	void calculateDerivedUrls(List<String> acUrls, List<String> expectedNetAcUrls,
			List<String> expectedOrigins, List<String> expectedRedirectUrls) {
		AcWhitelist acWhitelist = new AcWhitelist(acUrls);
		acWhitelist.calculateDerivedUrls();
		assertThat(acWhitelist.getAcNetUrls(), is(expectedNetAcUrls));
		assertThat(acWhitelist.getOrigins(), is(expectedOrigins));
		assertThat(acWhitelist.getRedirectUrls(), is(expectedRedirectUrls));
	}

	static Object[][] calculateDerivedUrls() throws URISyntaxException {
		return new Object[][] {
				{
					null, Collections.emptyList(), Collections.emptyList(), Collections.emptyList()
				},
				{
					List.of("null", "/relative", "https://example.trustbroker.swiss/path",
							"custom://app/command", "https://any.*.example.trustbroker.swiss/path", "https://test.example.trustbroker.swiss/#fragment"),
					List.of(new URI("https://example.trustbroker.swiss/path"), new URI("custom://app/command"),
							new URI("https://any.*.example.trustbroker.swiss/path"),
							new URI("https://test.example.trustbroker.swiss/#fragment")),
					List.of("https://example.trustbroker.swiss", "custom://app", "https://test.example.trustbroker.swiss"),
						List.of("https://example.trustbroker.swiss/path", "custom://app/command",
								"https://any.*.example.trustbroker.swiss/path"),
				}
		};
	}

}
