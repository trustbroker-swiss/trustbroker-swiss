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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class OidcMapperTest {

	@ParameterizedTest
	@MethodSource
	void mapObjectTimeEpoch(Object input, Object expected) {
		assertThat(OidcMapper.TIME_EPOCH.map(input), is(expected));
	}

	static Object[][] mapObjectTimeEpoch() {
		return new Object[][] {
				{ null, null },
				{ "", "" },
				{ "text", "text" },
				{ Boolean.TRUE, Boolean.TRUE },
				{ "1970-01-01T00:00:00Z", 0l },
				{ "2001-09-09T01:46:40Z", 1_000_000_000l },
				{ "2001-09-09T02:46:40+01:00[Europe/Paris]", 1_000_000_000l },
				{ Instant.ofEpochMilli(1_000_000_000_000l), 1_000_000_000l },
				{ new Date(1_000_000_000_000l), 1_000_000_000l },
		};
	}

	@ParameterizedTest
	@MethodSource
	void mapObjectTimeBoolean(Object input, Object expected) {
		assertThat(OidcMapper.BOOLEAN.map(input), is(expected));
	}

	static Object[][] mapObjectTimeBoolean() {
		return new Object[][] {
				{ null, null },
				{ "", "" },
				{ "text", "text" },
				{ Boolean.TRUE, Boolean.TRUE },
				{ "true", Boolean.TRUE },
				{ "True", Boolean.TRUE },
				{ "TRUE", Boolean.TRUE },
				{ "false", Boolean.FALSE },
				{ "False", Boolean.FALSE },
				{ "FALSE", Boolean.FALSE },
		};
	}

	@ParameterizedTest
	@MethodSource
	void mapObjectTimeSwissSocialSecurityNo(Object input, Object expected) {
		assertThat(OidcMapper.SWISS_SOCIAL_SECURITY_NO.map(input), is(expected));
	}

	static Object[][] mapObjectTimeSwissSocialSecurityNo() {
		return new Object[][] {
				{ null, null },
				{ "", "" },
				{ "text", "text" },
				{ Boolean.TRUE, Boolean.TRUE },
				{ "7561234567890", 7561234567890l },
				{ "756.1234.5678.90", 7561234567890l },
				{ "7561234.5678.90", 7561234567890l },
				{ "756.1234.5678.901", "756.1234.5678.901" },
				{ "9756.1234.5678.901", "9756.1234.5678.901" },
		};
	}

	@ParameterizedTest
	@MethodSource
	void mapObjectListTimeEpoch(List<Object> input, Object expected) {
		assertThat(OidcMapper.TIME_EPOCH.map(input), is(expected));
	}

	static Object[][] mapObjectListTimeEpoch() {
		return new Object[][] {
				{ null, null },
				{ Collections.emptyList(), Collections.emptyList() },
				{ List.of("test", "1973-03-03T09:46:40Z", Instant.ofEpochMilli(123_456_789l), Integer.MAX_VALUE),
						List.of("test", 100_000_000l, 123_456l, Integer.MAX_VALUE) }
		};
	}

}
