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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import swiss.trustbroker.api.profileselection.dto.ProfileSelectionResult;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.OidcProperties;
import swiss.trustbroker.federation.xmlconfig.ConstAttributes;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.saml.dto.CpResponse;
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
		var result = DefinitionUtil.findByNameOrNamespace(inputName, null, input);
		validateAttributes(expected, result, definition);

		var resultDefinition = DefinitionUtil.findByNameOrNamespace(new Definition(inputName), null, input);
		validateAttributes(expected, resultDefinition, definition);

		var resultCp = DefinitionUtil.findAttributeByNameOrNamespace(inputName, null, inputCp);
		validateAttributes(expected, resultCp, definition);

		Map<AttributeName, List<String>> attributes = Map.of(
				Definition.ofName(CoreAttributeName.NAME), List.of("other"),
				Definition.builder()
							 .name(definitionName)
							 .namespaceUri(definitionNamespace)
							 .build(),
				List.of(expected));
		Map<AttributeName, List<String>> cpAttributes = new HashMap<>(attributes);
	}

	static String[][] findByNameOrNamespace() {
		return new String[][] {
				{ "attribute1", "attribute1", "https://domain/path/name", "value1" },
				{ "https://domain/path/name", "attribute1", "https://domain/path/name", "value1" },
				{ "other", "attribute1", "https://domain/path/name", "" },
		};
	}

	private static <T extends AttributeName, V> void validateAttributes(String expected, Optional<Map.Entry<T, String>> result,
			Definition definition) {
		if (expected.isEmpty()) {
			assertThat(result.isPresent(), is(false));
		}
		else {
			assertThat(result.isPresent(), is(true));
			assertThat(result.get()
							 .getKey(), is(definition));
			assertThat(result.get()
							 .getValue(), is(expected));
		}
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

		var resultDefinition = DefinitionUtil.findListByNameOrNamespace(new Definition(inputName), input);
		assertThat(result, is(resultDefinition));

		var expectedValue = expected.isEmpty() ? null : expected.get(0);
		var singleValue = DefinitionUtil.findSingleValueByNameOrNamespace(inputName, input);
		assertThat(singleValue, is(expectedValue));

		var singleValueDefinition = DefinitionUtil.findSingleValueByNameOrNamespace(new Definition(inputName), input);
		assertThat(singleValueDefinition, is(expectedValue));

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

	@ParameterizedTest
	@MethodSource
	void findAllByNameOrNamespace(String inputName, Map<AttributeName, List<String>>  inputAttributes,
			Map<AttributeName, List<String>> expectedAttributes) {
		var result = DefinitionUtil.findAllByNameOrNamespace(inputName, null, inputAttributes);
		assertThat(result, is(expectedAttributes));
	}

	static Object[][] findAllByNameOrNamespace() {
		return new Object[][] {
				{
						CoreAttributeName.FIRST_NAME.getNamespaceUri(),
						givenAttributeMap(),
						givenAttributeMapFilteredByFirstNameNamespaceUri()
				},
				{
						CoreAttributeName.EMAIL.getName(),
						Map.of(CoreAttributeName.FIRST_NAME, List.of("name4"),
								CoreAttributeName.AUTH_LEVEL, List.of("name5")),
						Collections.emptyMap()
				},
		};
	}

	@ParameterizedTest
	@MethodSource
	void findAllAttributesByAttributeNameOrNamespace(AttributeName inputName, Map<AttributeName, List<String>>  inputAttributes,
			Map<AttributeName, List<String>> expectedAttributes) {
		var result = DefinitionUtil.findAllByNameOrNamespace(inputName, null, inputAttributes);
		assertThat(result, is(expectedAttributes));
	}

	static Object[][] findAllAttributesByAttributeNameOrNamespace() {
		return new Object[][] {
				{
						CoreAttributeName.FIRST_NAME,
						givenAttributeMap(),
						givenAttributeMapFilteredByFirstNameNamespaceUri()
				},
				{
						CoreAttributeName.EMAIL,
						Map.of(CoreAttributeName.FIRST_NAME, List.of("name4"),
								CoreAttributeName.AUTH_LEVEL, List.of("name5")),
						Collections.emptyMap()
				},
		};
	}

	private static Map<AttributeName, List<String>> givenAttributeMap() {
		return Map.of(CoreAttributeName.FIRST_NAME, List.of("name1"),
				Definition.ofNamespaceUri(CoreAttributeName.FIRST_NAME), List.of("name2"),
				CoreAttributeName.CLAIMS_NAME, List.of("wrong"),
				new Definition(null, CoreAttributeName.FIRST_NAME.getNamespaceUri()), List.of("name3"));
	}

	private static Map<AttributeName, List<String>> givenAttributeMapFilteredByFirstNameNamespaceUri() {
		return Map.of(CoreAttributeName.FIRST_NAME, List.of("name1"),
				Definition.ofNamespaceUri(CoreAttributeName.FIRST_NAME), List.of("name2"),
				new Definition(null, CoreAttributeName.FIRST_NAME.getNamespaceUri()), List.of("name3"));
	}

	@Test
	void mapCpAttributeList() {
		var firstName = List.of("first1");
		var lastName = List.of("last1");
		Map<AttributeName, List<String>> attributes = Map.of(
				Definition.ofName(CoreAttributeName.NAME), lastName,
				// test Definition implementation that is not Definition
				Definition.ofName(
						SamlTestBase.TestAttributeName.of(CoreAttributeName.FIRST_NAME)), firstName);
		Map<Definition, List<String>> expected = Map.of(
				Definition.builder().name(CoreAttributeName.NAME.getName()).build(), lastName,
				Definition.builder().name(CoreAttributeName.FIRST_NAME.getName()).build(), firstName);

		HashMap<Definition, List<String>> result = new HashMap<>();
		DefinitionUtil.mapCpAttributeList(attributes, result);
		assertThat(result, is(expected));

		Map<Definition, List<String>> definitions = new HashMap<>();
		DefinitionUtil.mapCpAttributeList(attributes, definitions);
		assertThat(definitions, is(expected));
	}

	@ParameterizedTest
	@MethodSource
	void putAttributeValue(AttributeName attribute, String value, List<String> expected) {
		var attributeDefinition = Definition.builder()
											   .name(attribute.getName())
											   .namespaceUri(attribute.getNamespaceUri())
											   .build();
		Map<AttributeName, List<String>> cpAttributes = new HashMap<>();
		DefinitionUtil.putAttributeDefinitionValue(cpAttributes, attribute.getName(), attribute.getNamespaceUri(), value);
		assertThat(cpAttributes.get(attributeDefinition), is(expected));

		Map<AttributeName, List<String>> attrs = new HashMap<>();
		DefinitionUtil.putAttributeDefinitionValue(attrs, attribute.getName(), attribute.getNamespaceUri(), value);
		assertThat(attrs.get(attributeDefinition), is(expected));

		cpAttributes = new HashMap<>();
		DefinitionUtil.putAttributeDefinitionValue(cpAttributes, attribute.getName(), attribute.getNamespaceUri(), value);
		assertThat(cpAttributes.get(attributeDefinition), is(expected));

		Map<Definition, List<String>> attributes = new HashMap<>();
		attributes = new HashMap<>();
		DefinitionUtil.putDefinitionValue(attributes, attribute.getName(), attribute.getNamespaceUri(), null, value);
		assertThat(attributes.get(new Definition(attribute)), is(expected));
	}

	static Object[][] putAttributeValue() {
		return new Object[][] {
				{ CoreAttributeName.FIRST_NAME, null, List.of(DefinitionUtil.VALUE_TO_LIST_NULL) },
				{ CoreAttributeName.NAME, "lastName1", List.of("lastName1") },
		};
	}

	@Test
	void attributeToDropEmptyTest(){
		var definition = new Definition("attr1");
		List<String> attributesToBeDropped = Collections.emptyList();
		Map<Definition, List<String>> userDetails = new HashMap<>();
		Map<Definition, List<String>> properties = new HashMap<>();
		var constAttributes = mock(ConstAttributes.class);

		boolean result = DefinitionUtil.attributeToDrop(definition, attributesToBeDropped, userDetails, properties, constAttributes);

		assertFalse(result, "Result should be false when attributesToBeDropped is empty.");

	}

	@Test
	void attributeToDropNoInListTest(){
		Definition definition = Definition.ofNamespaceUri(CoreAttributeName.FIRST_NAME);
		List<String> attributesToBeDropped = List.of("otherAttr");
		Map<Definition, List<String>> userDetails = new HashMap<>();
		Map<Definition, List<String>> properties = new HashMap<>();
		ConstAttributes constAttributes = mock(ConstAttributes.class);

		boolean result = DefinitionUtil.attributeToDrop(definition, attributesToBeDropped, userDetails, properties, constAttributes);

		assertFalse(result, "Result should be false when the attribute is not in the list of attributes to be dropped.");

	}

	@Test
	void attributeToDropInListTest() {
		Definition definition = Definition.ofNamespaceUri(CoreAttributeName.FIRST_NAME);
		List<String> attributesToBeDropped = Collections.singletonList(CoreAttributeName.FIRST_NAME.getNamespaceUri());
		Map<Definition, List<String>> userDetails = new HashMap<>();
		userDetails.put(definition, List.of("someValue"));
		Map<Definition, List<String>> properties = new HashMap<>();
		ConstAttributes constAttributes = mock(ConstAttributes.class);

		boolean result = DefinitionUtil.attributeToDrop(definition, attributesToBeDropped, userDetails, properties, constAttributes);

		assertTrue(result, "Result should be true when the attribute is in the list and is present in userDetails.");

	}

	@Test
	void isXtbDestinationDestinationTest() {
		var trustBrokerProperties = new TrustBrokerProperties();
		var oidcProperties = new OidcProperties();
		oidcProperties.setPerimeterUrl("https://example.com");
		trustBrokerProperties.setOidc(oidcProperties);

		boolean result = DefinitionUtil.isXtbDestination(trustBrokerProperties, null);

		assertFalse(result, "Result should be false when the destination is null.");

		assertFalse(DefinitionUtil.isXtbDestination(trustBrokerProperties, "invalid-url"));
	}

	@Test
	void isXtbDestinationPerimeterUrlTest(){
		var trustBrokerProperties = new TrustBrokerProperties();
		var oidcProperties = new OidcProperties();
		oidcProperties.setPerimeterUrl(null);
		trustBrokerProperties.setOidc(oidcProperties);

		boolean result = DefinitionUtil.isXtbDestination(trustBrokerProperties, "https://example.com");

		assertFalse(result, "Result should be false when the OIDC perimeter URL is null.");

		trustBrokerProperties.getOidc().setPerimeterUrl("invalid-url");

		assertFalse(DefinitionUtil.isXtbDestination(trustBrokerProperties, "https://example.com"));
	}

	@Test
	void isXtbDestinationHostMatchTest() {
		var trustBrokerProperties = new TrustBrokerProperties();
		var oidcProperties = new OidcProperties();
		oidcProperties.setPerimeterUrl("https://example.com");
		trustBrokerProperties.setOidc(oidcProperties);

		boolean resultTrue = DefinitionUtil.isXtbDestination(trustBrokerProperties, "https://example.com/some-path");

		assertTrue(resultTrue, "Result should be true when the hosts of the destination and perimeter URL match.");

		boolean resultFalse = DefinitionUtil.isXtbDestination(trustBrokerProperties, "https://different.com");
		assertFalse(resultFalse, "Result should be false when the hosts of the destination and perimeter URL do not match.");
	}

	@Test
	void applyProfileSelectionTest() {
		var cpResponse = givenCpResponse();
		var userDetails = cpResponse.getUserDetails();

		DefinitionUtil.applyProfileSelection(cpResponse, null);
		assertEquals(userDetails, cpResponse.getUserDetails());

		Map<AttributeName, List<String>> psUserDetails = givenPSResultUserDetails();
		var psResult = ProfileSelectionResult.builder()
											 .filteredAttributes(Optional.of(psUserDetails))
											 .build();
		DefinitionUtil.applyProfileSelection(cpResponse, psResult);
		assertNotEquals(userDetails, cpResponse.getUserDetails());
		assertTrue(cpResponse.getUserDetails().entrySet().stream()
				.filter(map -> map.getKey().getName().equals(CoreAttributeName.CLAIMS_NAME.getName()))
				.findFirst().isPresent());
	}

	@Test
	void definitionAndValueEqualsTest() {
		var def1 = Definition.builder()
									.name(CoreAttributeName.FIRST_NAME.getName())
									.namespaceUri(CoreAttributeName.FIRST_NAME.getNamespaceUri())
									.build();
		var def2 = Definition.builder()
									.name(CoreAttributeName.EMAIL.getName())
									.namespaceUri(CoreAttributeName.EMAIL.getNamespaceUri())
									.build();

		assertFalse(DefinitionUtil.definitionAndValueEquals(def1, null, def2, null));

		def2.setNamespaceUri(CoreAttributeName.FIRST_NAME.getNamespaceUri());
		assertTrue(DefinitionUtil.definitionAndValueEquals(def1, null, def2, null));

		assertFalse(DefinitionUtil.definitionAndValueEquals(def1, List.of("any"), def2, null));

		def2.setNamespaceUri(null);
		assertFalse(DefinitionUtil.definitionAndValueEquals(def1, null, def2, null));

		def2.setName(CoreAttributeName.FIRST_NAME.getName());
		assertTrue(DefinitionUtil.definitionAndValueEquals(def1, null, def2, null));

		assertFalse(DefinitionUtil.definitionAndValueEquals(def1, List.of("any"), def2, null));
	}

	@Test
	void listMatchTest(){
		assertTrue(DefinitionUtil.listMatch(null, null));

		assertTrue(DefinitionUtil.listMatch(List.of("name1", "name2"), List.of("name2", "name1")));

		assertFalse(DefinitionUtil.listMatch(List.of("name1", "name4"), List.of("name2", "name1")));
	}

	@Test
	void filterAndCreateCpDefinitionsExceptionTest() {
		var confAttributes = Collections.singletonList(new Definition("attr1"));


		assertThrows(TechnicalException.class, () ->
				DefinitionUtil.filterAndCreateCpDefinitions(null, confAttributes)
		);
	}

	@Test
	void filterAndCreateCpDefinitionsIsEmptyTest() {
		Map<Definition, List<String>> attributes = new HashMap<>();
		Collection<Definition> confAttributes = Collections.emptyList();

		Map<Definition, List<String>> result = DefinitionUtil.filterAndCreateCpDefinitions(attributes, confAttributes);

		assertTrue(result.isEmpty(), "Result should be an empty map when confAttributes is empty.");
	}

	@Test
	void filterAndCreateCpDefinitionsTest() {
		Map<Definition, List<String>> attributes = new HashMap<>();
		Definition definition1 = new Definition("attr1");
		Definition definition2 = new Definition("attr2");

		List<String> values1 = Arrays.asList("value1", "value2");
		List<String> values2 = Arrays.asList("value3", "value4");

		attributes.put(definition1, values1);
		attributes.put(definition2, values2);

		Collection<Definition> confAttributes = List.of(definition1);

		Map<Definition, List<String>> result = DefinitionUtil.filterAndCreateCpDefinitions(attributes, confAttributes);

		assertEquals(1, result.size());
		assertTrue(result.containsKey(definition1));
	}

	@Test
	void deduplicatedRpAttributesTest() {
		Map<Definition, List<String>> userDetailMap = new HashMap<>();
		Map<Definition, List<String>> properties = new HashMap<>();
		ConstAttributes constAttributes = mock(ConstAttributes.class);

		var result = DefinitionUtil.deduplicatedRpAttributes(userDetailMap, properties, constAttributes);

		assertTrue(result.isEmpty(), "Result should be an empty map when the userDetailMap is empty.");

		Definition definition1 = new Definition("attr1", CoreAttributeName.CLAIMS_NAME.getNamespaceUri());
		List<String> values1 = List.of("value1");
		Definition definition2 = new Definition("attr2");
		List<String> values2 = List.of("value2");
		Definition definition3 = new Definition("attr3", CoreAttributeName.CLAIMS_NAME.getNamespaceUri());
		userDetailMap.put(definition1, values1);
		userDetailMap.put(definition2, values2);
		userDetailMap.put(definition3, values1);

		result = DefinitionUtil.deduplicatedRpAttributes(userDetailMap, properties, constAttributes);
		assertFalse(result.isEmpty());
		assertTrue(result.size() < userDetailMap.size());

		properties.put(definition3, values1);
		result = DefinitionUtil.deduplicatedRpAttributes(userDetailMap, properties, constAttributes);
		assertFalse(result.isEmpty());
		assertTrue(result.size() < userDetailMap.size());

	}

	@Test
	void mapContainsDefinitionWithValueTest() {
		Map<Definition, List<String>> attributes = new HashMap<>();
		Definition definition = new Definition("attr1");
		List<String> value = List.of("value1");

		assertFalse(DefinitionUtil.mapContainsDefinitionWithValue(attributes, definition, value),
				"Result should be false when the attributes map is empty.");

		Definition matchingDefinition = new Definition("attr1");
		attributes.put(matchingDefinition, value);
		assertTrue(DefinitionUtil.mapContainsDefinitionWithValue(attributes, definition, value));
		assertFalse(DefinitionUtil.mapContainsDefinitionWithValue(attributes, definition,  List.of("othervalue")));

		Definition notMatchingDefinition = new Definition("otherName");
		assertFalse(DefinitionUtil.mapContainsDefinitionWithValue(attributes, notMatchingDefinition, value));
	}

	@ParameterizedTest
	@MethodSource
	void equalsByName(AttributeName first, AttributeName second, boolean expectedResult) {
		assertThat(first.equalsByName(second), is(expectedResult));
		assertThat(first.equalsByName(second != null ? second.getName() : null), is(expectedResult));
	}

	static Object[][] equalsByName() {
		return new Object[][] {
				{ CoreAttributeName.FIRST_NAME, null, false },
				{ CoreAttributeName.FIRST_NAME, CoreAttributeName.FIRST_NAME, true },
				{ CoreAttributeName.FIRST_NAME, CoreAttributeName.EMAIL, false },
				{ CoreAttributeName.FIRST_NAME, Definition.ofName(CoreAttributeName.FIRST_NAME), true },
				{ CoreAttributeName.FIRST_NAME, Definition.ofName(CoreAttributeName.NAME), false },
				{ CoreAttributeName.FIRST_NAME, Definition.ofNamespaceUri(CoreAttributeName.FIRST_NAME), false }
		};
	}

	@ParameterizedTest
	@MethodSource
	void equalsByNamespace(AttributeName first, String namespace, boolean expectedResult) {
		assertThat(first.equalsByNamespace(namespace), is(expectedResult));
	}

	static Object[][] equalsByNamespace() {
		return new Object[][] {
				{ CoreAttributeName.FIRST_NAME, null, false },
				{ CoreAttributeName.FIRST_NAME, CoreAttributeName.FIRST_NAME.getNamespaceUri(), true },
				{ CoreAttributeName.FIRST_NAME, Definition.ofNamespaceUri(CoreAttributeName.FIRST_NAME).getName(), true },
				{ CoreAttributeName.FIRST_NAME, CoreAttributeName.EMAIL.getNamespaceUri(), false }
		};
	}

	@ParameterizedTest
	@MethodSource
	void equalsByNameAndNamespace(AttributeName first, AttributeName second, boolean expectedResult) {
		assertThat(first.equalsByNameAndNamespace(second), is(expectedResult));
	}

	static Object[][] equalsByNameAndNamespace() {
		return new Object[][] {
				{ CoreAttributeName.FIRST_NAME, null, false },
				{ CoreAttributeName.FIRST_NAME, CoreAttributeName.FIRST_NAME, true },
				{ CoreAttributeName.FIRST_NAME, CoreAttributeName.EMAIL, false },
				{ CoreAttributeName.FIRST_NAME, Definition.ofNames(CoreAttributeName.FIRST_NAME), true },
				{ CoreAttributeName.FIRST_NAME, new Definition(CoreAttributeName.FIRST_NAME.getName(),
						CoreAttributeName.NAME_ID.getNamespaceUri()), false },
				{ CoreAttributeName.FIRST_NAME, new Definition(CoreAttributeName.HOME_NAME.getName(),
						CoreAttributeName.FIRST_NAME.getNamespaceUri()), false }
		};
	}

	@ParameterizedTest
	@MethodSource
	void equalsByNameOrNamespace(AttributeName first, AttributeName second, boolean expectedResult) {
		assertThat(first.equalsByNameOrNamespace(second), is(expectedResult));
	}

	static Object[][] equalsByNameOrNamespace() {
		return new Object[][] {
				{ CoreAttributeName.FIRST_NAME, null, false },
				{ CoreAttributeName.FIRST_NAME, CoreAttributeName.FIRST_NAME, true },
				{ CoreAttributeName.FIRST_NAME, CoreAttributeName.EMAIL, false },
				{ CoreAttributeName.FIRST_NAME, new Definition(CoreAttributeName.FIRST_NAME.getName(),
						CoreAttributeName.NAME_ID.getNamespaceUri()), true },
				{ CoreAttributeName.FIRST_NAME, new Definition(CoreAttributeName.HOME_NAME.getName(),
						CoreAttributeName.FIRST_NAME.getNamespaceUri()), true },
				// AttributeName compares the same type
				{ CoreAttributeName.FIRST_NAME, new Definition(CoreAttributeName.FIRST_NAME.getNamespaceUri(),
						CoreAttributeName.FIRST_NAME.getName()), false },
				// Definition compares cross-wise
				{ new Definition(CoreAttributeName.FIRST_NAME.getNamespaceUri(), CoreAttributeName.FIRST_NAME.getName()),
						CoreAttributeName.FIRST_NAME, true },
				{ new Definition(CoreAttributeName.FIRST_NAME.getNamespaceUri(), null),
						CoreAttributeName.FIRST_NAME, true },
				{ new Definition(null, CoreAttributeName.FIRST_NAME.getName()),
						CoreAttributeName.FIRST_NAME, true }
		};
	}

	private static CpResponse givenCpResponse() {
		Map<Definition, List<String>> attributeValueMap = new HashMap<>();
		attributeValueMap.put(new Definition(CoreAttributeName.EMAIL), List.of("email"));
		return CpResponse.builder()
						 .attributes(attributeValueMap)
						 .userDetails(givenUserDetails())
						 .build();
	}

	private static Map<Definition, List<String>> givenUserDetails() {
		return Map.of(
				Definition.ofNamespaceUri(CoreAttributeName.FIRST_NAME), List.of(
						"first_name_1"),
				Definition.ofNamespaceUri(CoreAttributeName.NAME), List.of(
						"family_name_1"));
	}

	private static Map<AttributeName, List<String>> givenPSResultUserDetails() {
		return Map.of(
				 SamlTestBase.TestAttributeName.of(CoreAttributeName.CLAIMS_NAME), List.of(
						"first_name_1"),
				SamlTestBase.TestAttributeName.of(CoreAttributeName.NAME), List.of(
						"family_name_1"));
	}
}
