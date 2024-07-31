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

package swiss.trustbroker.audit.service;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.slf4j.LoggerFactory;
import swiss.trustbroker.audit.dto.AuditDto;
import swiss.trustbroker.audit.dto.EventType;

class AuditLogBuilderTest {

	@BeforeEach
	void setUp() {
		// we misuse the AuditLogger also as a config to flag message and postfix emitting
		var log = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(AuditLogger.class.getName());
		log.setLevel(ch.qos.logback.classic.Level.TRACE);
		assertThat(AuditLogger.isAdditionalAuditingEnabled(), is(true)); // with FQ names
		assertThat(AuditLogger.isDetailAuditingEnabled(), is(false)); // without saml message detail
	}

	@Test
	void testEmpty() {
		AuditLogBuilder auditLogBuilder = new AuditLogBuilder();
		String result = auditLogBuilder.build();
		assertThat(result, is(""));
	}

	@Test
	void testPrefix() {
		String prefix = "something";
		AuditLogBuilder auditLogBuilder = new AuditLogBuilder(prefix);
		String result = auditLogBuilder.build();
		assertThat(result, is(prefix));
	}

	@ParameterizedTest
	@CsvSource({
			",value,postfix,",
			"key,,postfix,",
			"simple,something,,simple=something",
			"dashes-to-underscores,value-with-dashes-quoted,,dashes_to_underscores=\"value-with-dashes-quoted\"",
			"space key,space value,,\"space key\"=\"space value\"",
			"astring,The quick brown fox,,astring=\"The quick brown fox\"",
			"\"quoted\" value,A \"special\" case,,\"\\\"quoted\\\" value\"=\"A \\\"special\\\" case\"",
			"name,value,postfix,name=\"value (postfix)\"",
	})
	void testKeyValue(String key, String value, String postfix, String expected) {
		AuditLogBuilder auditLogBuilder = new AuditLogBuilder();
		auditLogBuilder.append(key, value, postfix);
		String result = auditLogBuilder.build();
		if (expected == null) {
			expected = ""; // empty string for expected, but null for inputs -> cannot use CsvSource.emptyValue
		}
		assertThat(result, is(expected));
	}

	@Test
	void testList() {
		AuditLogBuilder auditLogBuilder = new AuditLogBuilder();
		auditLogBuilder.append("roles", List.of("one", "two", "three"));
		String result = auditLogBuilder.build();
		assertThat(result, is("roles=\"[one, two, three]\""));
	}

	@Test
	void testSet() {
		AuditLogBuilder auditLogBuilder = new AuditLogBuilder();
		Set<Integer> set = new TreeSet<>(); // ensure stable toString with TreeSet
		set.add(1);
		set.add(2);
		auditLogBuilder.append("roles", set);
		String result = auditLogBuilder.build();
		assertThat(result, is("roles=\"[1, 2]\""));
	}

	@Test
	void testMap() {
		AuditLogBuilder auditLogBuilder = new AuditLogBuilder();
		Map<String, List<String>> map = new TreeMap<>(); // ensure stable toString with TreeMap
		map.put("key1", List.of("one"));
		map.put("key2", List.of("two, three"));
		auditLogBuilder.append("complex", map);
		String result = auditLogBuilder.build();
		assertThat(result, is("complex=\"{key1=[one], key2=[two, three]}\""));
	}

	@Test
	void testSingletonList() {
		AuditLogBuilder auditLogBuilder = new AuditLogBuilder();
		auditLogBuilder.append("roles", Collections.singletonList("theoneandonly"));
		String result = auditLogBuilder.build();
		assertThat(result, is("roles=theoneandonly"));
	}

	@Test
	void testEmptySet() {
		AuditLogBuilder auditLogBuilder = new AuditLogBuilder();
		auditLogBuilder.append("roles", Collections.emptySet());
		String result = auditLogBuilder.build();
		assertThat(result, is("roles="));
	}

	@Test
	void testCombined() {
		AuditLogBuilder auditLogBuilder = new AuditLogBuilder("Test line: ");
		auditLogBuilder.append("url", "https://example.trustbroker.swiss/api?test");
		auditLogBuilder.append("count", 42);
		auditLogBuilder.append("name", "John Doe");
		auditLogBuilder.append("login", "X12345678");
		String result = auditLogBuilder.build();
		assertThat(result, is("Test line: url=\"https://example.trustbroker.swiss/api?test\", count=42, name=\"John Doe\", login=X12345678"));
	}

	@Test
	void testAppendDto() {
		AuditDto auditDto = AuditDto.builder()
				.conversationId("1af312")
				.destination("target")
				.eventType(EventType.RESPONSE)
				.responseAttributes(Map.of(
						"custom", AuditDto.ResponseAttributeValue.of(List.of("single"), null,
								AuditDto.AttributeSource.IDP_RESPONSE, 1),
						"decided", AuditDto.ResponseAttributeValue.of(List.of("yes"), "maybe",
								AuditDto.AttributeSource.IDP_RESPONSE, 1)
				))
				.build();
		AuditLogBuilder auditLogBuilder = new AuditLogBuilder();
		auditLogBuilder.appendDtoFields(auditDto);
		String result = auditLogBuilder.build();
		assertThat(Arrays.asList(result.split(", ")),
				allOf(
						containsInAnyOrder("conversationId=1af312", "destination=target",
								"custom=\"single (@c)\"", "decided=\"yes (@c maybe)\""),
						not(contains("samlType=RESPONSE"))
				));
	}

}
