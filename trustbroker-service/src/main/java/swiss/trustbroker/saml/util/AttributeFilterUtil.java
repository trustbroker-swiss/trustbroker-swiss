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

package swiss.trustbroker.saml.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import swiss.trustbroker.audit.dto.AuditDto;
import swiss.trustbroker.federation.xmlconfig.AttributesSelection;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.IdmLookup;
import swiss.trustbroker.federation.xmlconfig.IdmQuery;
import swiss.trustbroker.federation.xmlconfig.MultiQueryResultPolicy;

public class AttributeFilterUtil {

	private AttributeFilterUtil(){}

	public static Definition getDefinitionFromMap(Map<Definition, List<String>> map, Definition definition) {
		for (Map.Entry<Definition, List<String>> entry : map.entrySet()) {
			var key = entry.getKey();
			if (definition.getNamespaceUri() != null && key.getNamespaceUri() != null) {
				return definition.equalsByNamespace(key.getNamespaceUri()) ? key : null;
			}
			if (definition.equalsByNameOrNamespace(definition)) {
				return key;
			}
		}
		return null;
	}

	public static Map<Definition, List<String>> filteredUserDetails(Map<Definition, List<String>> userDetailMap,
			IdmLookup idmLookup) {
		Map<Definition, List<String>> responseAttrs = new HashMap<>();
		if (userDetailMap == null) {
			return responseAttrs;
		}

		// Source is null if the attributes was created in a script, in the implementation,
		// or it is an old session in DB from a prev app version
		for (Map.Entry<Definition, List<String>> entry : userDetailMap.entrySet()) {
			var attributeDefinition = entry.getKey();
			var values = new ArrayList<>(entry.getValue());
			var source = attributeDefinition.getSource();
			// Groovy scripts should not manipulate user details, but we did not prevent that by design, accept it here
			if (source == null || AuditDto.AttributeSource.SCRIPT.name().equals(source)) {
				responseAttrs.put(new Definition(attributeDefinition.getName(), attributeDefinition.getNamespaceUri()), values);
			}
		}

		if (idmLookup == null || idmLookup.getQueries() == null) {
			return responseAttrs;
		}

		applyMultiQueryPolicies(userDetailMap, idmLookup, responseAttrs);
		return responseAttrs;
	}

	// Pick attributes for queries to make sure MultiQueryPolicy applied correctly
	private static void applyMultiQueryPolicies(Map<Definition, List<String>> userDetailMap, IdmLookup idmLookup,
			Map<Definition, List<String>> responseAttrs) {
		var multiQueryPolicy = idmLookup.getMultiQueryPolicy();
		List<IdmQuery> queries = idmLookup.getQueries();
		for (IdmQuery idmQuery : queries) {
			if (idmQuery.getUserDetailsSelection() == null) {
				continue;
			}
			for (Definition configDefinition : idmQuery.getUserDetailsSelection().getDefinitions()) {
				// Create the attribute if the Definition is in the config
				var attributeValue = getAttributeValueIfRequiredForOutput(userDetailMap, configDefinition, idmQuery.getName());
				if (attributeValue.isPresent()) {
					var definition = Definition.ofNames(configDefinition);
					var source = attributeValue.get().getKey().getSource();
					var value = new ArrayList<>(attributeValue.get().getValue());
					definition.setSource(source);
					applyMultiQueryPolicy(multiQueryPolicy, responseAttrs, definition, value);
				}
			}
		}
	}

	private static Optional<Map.Entry<Definition, List<String>>> getAttributeValueIfRequiredForOutput(
			Map<Definition, List<String>> userDetailMap, Definition configDefinition, String name) {
		for (Map.Entry<Definition, List<String>> entry : userDetailMap.entrySet()) {
			var attributeDefinition = entry.getKey();
			// Attribute definition does not have NamespaceUri yet
			if (attributeDefinition.getSource() != null  && configDefinition.getName().equals(attributeDefinition.getName())
					&& Objects.equals(attributeDefinition.getSource(), name)) {
					return Optional.of(entry);
			}
		}
		return Optional.empty();
	}

	// Apply MultiQueryResultPolicy
	static void applyMultiQueryPolicy(MultiQueryResultPolicy multiQueryPolicy, Map<Definition, List<String>> respIdpAttributes,
			Definition definition, List<String> value) {
		var foundDef = getDefinitionFromMap(respIdpAttributes, definition);
		// Definition is already there from prev query
		if (foundDef != null) {
			if (multiQueryPolicy == null || multiQueryPolicy == MultiQueryResultPolicy.OVERWRITE) {
				respIdpAttributes.remove(foundDef);
				respIdpAttributes.put(definition, value);
			}
			else {
				respIdpAttributes.get(foundDef).addAll(value);
			}
		}
		else {
			respIdpAttributes.put(definition, value);
		}
	}

	public static Map<Definition, List<String>> filterProperties(Map<Definition, List<String>> properties,
			AttributesSelection attributesSelection) {
		return properties.entrySet().stream()
				.filter(map -> attributeMustBeInResponse(map.getKey(), attributesSelection))
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

	}

	private static boolean attributeMustBeInResponse(Definition attributeDefinition,
			AttributesSelection attributesSelection) {
		if (attributesSelection == null || attributesSelection.getDefinitions() == null) {
			return false;
		}
		List<Definition> definitions = attributesSelection.getDefinitions();
		for (Definition definition : definitions) {
			if (attributeDefinition.equalsByNameAndNamespace(definition)) {
				return true;
			}
		}
		return false;
	}

}
