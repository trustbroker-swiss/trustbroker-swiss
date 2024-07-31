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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.util.CollectionUtils;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;
import swiss.trustbroker.common.saml.util.AttributeRegistry;
import swiss.trustbroker.federation.xmlconfig.Definition;

@Slf4j
public class DefinitionUtil {

	static final String VALUE_TO_LIST_NULL = "XTB.DefinitionUtil.valueToList(null)";

	private DefinitionUtil() {
	}

	public static <T> Optional<Map.Entry<Definition, T>> findByNameOrNamespace(String name, Map<Definition, T> properties) {
		return properties.entrySet().stream()
				.filter(e -> e.getKey().equalsByNameOrNamespace(name))
				.findFirst();
	}

	public static <T> Optional<Map.Entry<AttributeName, T>> findCpAttributeByNameOrNamespace(String name,
			Map<AttributeName, T> properties) {
		return properties.entrySet().stream()
				.filter(e -> e.getKey().equalsByNameOrNamespace(name))
				.findFirst();
	}

	public static <T> List<T> findListByNameOrNamespace(String name, Map<Definition, List<T>> properties) {
		var entry = findByNameOrNamespace(name, properties);
		return entry.isPresent() ? entry.get().getValue() : Collections.emptyList();
	}

	public static <T> T findSingleValueByNameOrNamespace(String name, Map<Definition, List<T>> properties) {
		var list = findListByNameOrNamespace(name, properties);
		return CollectionUtils.isEmpty(list) ? null : list.get(0);
	}

	public static <T> List<T> findCpAttributeListByNameOrNamespace(String name, Map<AttributeName, List<T>> properties) {
		var entry = findCpAttributeByNameOrNamespace(name, properties);
		return entry.isPresent() ? entry.get().getValue() : Collections.emptyList();
	}

	// get namespace part after last slash or null if there is no slash
	public static String truncateNamespace(String namespaceUri) {
		var name = StringUtils.substringAfterLast(namespaceUri, '/');
		if (StringUtils.isNotEmpty(name)) {
			return name;
		}
		// StringUtils returns an empty string, that is less convenient for conditions
		return null;
	}

	public static void mapCpAttributeList(Map<AttributeName, List<String>> attributes, Map<Definition, List<String>> definitions) {
		if (attributes == null) {
			return;
		}
		for (var attribute : attributes.entrySet()) {
			var key = mapCpAttributeName(attribute.getKey());
			definitions.put(key, attribute.getValue());
		}
	}

	private static Definition mapCpAttributeName(AttributeName attributeName) {
		if (attributeName instanceof Definition definition) {
			return definition;
		}
		var attribute = AttributeRegistry.forName(attributeName.getNamespaceUri());
		if (attribute == null) {
			attribute = AttributeRegistry.forName(attributeName.getName());
		}
		return new Definition(attribute);
	}

	public static Map<Definition, List<String>> mapCpAttributeList(Map<AttributeName, List<String>> attributes) {
		Map<Definition, List<String>> filteredAttributes = new HashMap<>();
		for (var entry : attributes.entrySet()) {
			if (entry.getKey() instanceof Definition definition) {
				filteredAttributes.put(definition, entry.getValue());
			}
			else {
				filteredAttributes.put(new Definition(entry.getKey()), entry.getValue());
			}
		}
		return filteredAttributes;
	}

	public static void putAttributeValue(Map<AttributeName, List<String>> attributes,
			String name, String fqName, String value) {
		var newValue = valueToList(value);
		var key = Definition.builder().name(name).namespaceUri(fqName).build();
		attributes.put(key, newValue);
	}

	public static void putDefinitionValue(Map<Definition, List<String>> attributes,
			String name, String fqName, String value) {
		var newValue = valueToList(value);
		var key = Definition.builder().name(name).namespaceUri(fqName).build();
		attributes.put(key, newValue);
	}

	public static void putAttributeValue(Map<AttributeName, List<String>> attributes, AttributeName attribute, String value) {
		var newValue = valueToList(value);
		var key = new Definition(attribute);
		attributes.put(key, newValue);
	}

	public static void putDefinitionValue(Map<Definition, List<String>> attributes, AttributeName attribute, String value) {
		var newValue = valueToList(value);
		var key = new Definition(attribute);
		attributes.put(key, newValue);
	}

	private static ArrayList<String> valueToList(String value) {
		var newValue = new ArrayList<String>(); // mutable, as addAttribute extends
		newValue.add(value != null ? value : VALUE_TO_LIST_NULL); // signal invalid null usage
		return newValue;
	}

	public static void putCpAttributeValues(Map<AttributeName, List<String>> attributes,
			String name, String fqName, List<String> values) {
		var key = Definition.builder().name(name).namespaceUri(fqName).build();
		if (values == null) {
			values = valueToList(null);
		}
		attributes.put(key, values);
	}

	public static List<String> getCpAttributeValues(Map<AttributeName, List<String>> attributes, String name) {
		var ret = findCpAttributeByNameOrNamespace(name, attributes);
		return ret.map(Map.Entry::getValue).orElse(null);
	}

	public static String getCpAttributeValue(Map<AttributeName, List<String>> attributes, String name) {
		var ret = findCpAttributeByNameOrNamespace(name, attributes);
		return ret.isEmpty() || ret.get().getValue() == null || ret.get().getValue().isEmpty() ?
				null : ret.get().getValue().get(0);
	}

}
