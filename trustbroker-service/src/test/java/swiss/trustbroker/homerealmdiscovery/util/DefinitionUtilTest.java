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

package swiss.trustbroker.homerealmdiscovery.util;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.test.saml.util.SamlTestBase;

class DefinitionUtilTest {

	@ParameterizedTest
	@MethodSource
	void truncateNamespace(String input, String result) {
		assertThat(DefinitionUtil.truncateNamespace(input), is(result));
	}

	static String[][] truncateNamespace() {
		return new String[][] {
				{ null, null },
				{ "", null },
				{ "https://domain/path/name/", null },
				{ "simpleName", null },
				{ "https://domain/path/name", "name" },
		};
	}

	@ParameterizedTest
	@MethodSource
	void findByNameOrNamespace(String inputName, String definitionName, String definitionNamespace, String expected) {
		var definition = new Definition(definitionName, definitionNamespace);
		Map<Definition, String> input = Map.of(Definition.ofName(CoreAttributeName.NAME), "other", definition, expected);
		Map<AttributeName, String> inputCp = new HashMap<>(input);
		var result = DefinitionUtil.findByNameOrNamespace(inputName, input);
		validateAttributes(expected, result, definition);

		var resultCp = DefinitionUtil.findCpAttributeByNameOrNamespace(inputName, inputCp);
		validateAttributes(expected, resultCp, definition);

		Map<Definition, List<String>> attributes = Map.of(Definition.ofName(CoreAttributeName.NAME), List.of("other"),
				definition, List.of(expected));
		Map<AttributeName, List<String>> cpAttributes = new HashMap<>(attributes);
		var resultGet = DefinitionUtil.getCpAttributeValue(cpAttributes, inputName);
		assertThat(resultGet, is(expected.isEmpty() ? null : expected));

		var resultsGet = DefinitionUtil.getCpAttributeValues(cpAttributes, inputName);
		assertThat(resultsGet, is(expected.isEmpty() ? null : List.of(expected)));
	}

	private static <T extends AttributeName, V> void validateAttributes(String expected, Optional<Map.Entry<T, String>> result,
			Definition definition) {
		if (expected.isEmpty()) {
			assertThat(result.isPresent(), is(false));
		}
		else {
			assertThat(result.isPresent(), is(true));
			assertThat(result.get().getKey(), is(definition));
			assertThat(result.get().getValue(), is(expected));
		}
	}

	static String[][] findByNameOrNamespace() {
		return new String[][] {
				{ "attribute1", "attribute1", "https://domain/path/name", "value1" },
				{ "https://domain/path/name", "attribute1", "https://domain/path/name", "value1" },
				{ "other", "attribute1", "https://domain/path/name", "" },
		};
	}

	@ParameterizedTest
	@MethodSource
	void findListByNameOrNamespace(String inputName, String definitionName, String definitionNamespace, List<String> expected) {
		var definition = new Definition(definitionName, definitionNamespace);
		// empty expected indicate not found, put a dummy value in the map to distinguish it from found empty list
		var values = expected.isEmpty() ? List.of("dummy") : expected;
		Map<Definition, List<String>> input =
				Map.of(Definition.ofName(CoreAttributeName.NAME), List.of("other"), definition, values);
		var result = DefinitionUtil.findListByNameOrNamespace(inputName, input);
		assertThat(result, is(expected));
		var singleValue = DefinitionUtil.findSingleValueByNameOrNamespace(inputName, input);
		var expectedValue = expected.isEmpty() ? null : expected.get(0);
		assertThat(singleValue, is(expectedValue));

		Map<AttributeName, List<String>> inputCp =
				Map.of(Definition.ofName(CoreAttributeName.NAME), List.of("other"), definition, values);
		result = DefinitionUtil.findCpAttributeListByNameOrNamespace(inputName, inputCp);
		assertThat(result, is(expected));
	}

	static Object[][] findListByNameOrNamespace() {
		return new Object[][] {
				{ "attribute1", "attribute1", "https://domain/path/name", List.of("value1") },
				{ "https://domain/path/name", "attribute1", "https://domain/path/name", List.of("value1") },
				{ "other", "attribute1", "https://domain/path/name", Collections.emptyList() },
		};
	}

	@Test
	void mapCpAttributeList() {
		List<String> firstName = List.of("first1");
		var lastName = List.of("last1");
		Map<AttributeName, List<String>> attributes = Map.of(Definition.ofName(CoreAttributeName.NAME), lastName,
				// test Definition implementation that is not Definition
				SamlTestBase.TestAttributeName.of(CoreAttributeName.FIRST_NAME),
				firstName);
		Map<Definition, List<String>> expected = Map.of(Definition.ofName(CoreAttributeName.NAME), lastName,
				new Definition(CoreAttributeName.FIRST_NAME), firstName);

		var result = DefinitionUtil.mapCpAttributeList(attributes);
		assertThat(result, is(expected));

		Map<Definition, List<String>> definitions = new HashMap<>();
		DefinitionUtil.mapCpAttributeList(attributes, definitions);
		assertThat(definitions, is(expected));
	}

	@ParameterizedTest
	@MethodSource
	void putCpAttributeValue(AttributeName attribute, String value, List<String> expected) {
		Map<AttributeName, List<String>> cpAttributes = new HashMap<>();
		DefinitionUtil.putAttributeValue(cpAttributes, attribute, value);
		assertThat(cpAttributes.get(new Definition(attribute)), is(expected));

		Map<Definition, List<String>> attributes = new HashMap<>();
		DefinitionUtil.putDefinitionValue(attributes, attribute, value);
		assertThat(attributes.get(new Definition(attribute)), is(expected));

		cpAttributes = new HashMap<>();
		DefinitionUtil.putAttributeValue(cpAttributes, attribute.getName(), attribute.getNamespaceUri(), value);
		assertThat(cpAttributes.get(new Definition(attribute)), is(expected));

		attributes = new HashMap<>();
		DefinitionUtil.putDefinitionValue(attributes, attribute.getName(), attribute.getNamespaceUri(), value);
		assertThat(attributes.get(new Definition(attribute)), is(expected));

		cpAttributes = new HashMap<>();
		DefinitionUtil.putCpAttributeValues(cpAttributes, attribute.getName(), attribute.getNamespaceUri(),
				value != null ? List.of(value) : null);
		assertThat(cpAttributes.get(new Definition(attribute)), is(expected));
	}

	static Object[][] putCpAttributeValue() {
		return new Object[][] {
				{ CoreAttributeName.FIRST_NAME, null, List.of(DefinitionUtil.VALUE_TO_LIST_NULL) },
				{ CoreAttributeName.NAME, "lastName1", List.of("lastName1") },
		};
	}

}
