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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import swiss.trustbroker.api.profileselection.dto.ProfileSelectionResult;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;
import swiss.trustbroker.audit.dto.AuditDto;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.ConstAttributes;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.saml.dto.ResponseParameters;
import swiss.trustbroker.saml.util.AttributeFilterUtil;

@Slf4j
public class DefinitionUtil {

	static final String VALUE_TO_LIST_NULL = "XTB.DefinitionUtil.valueToList(null)";

	private DefinitionUtil() {
	}

	public static <T> Optional<Map.Entry<Definition, T>> findByNameOrNamespace(AttributeName name, String source,
			Map<Definition, T> definitions) {
		var ret = definitions.entrySet()
				.stream()
				.filter(e -> e.getKey().equalsByNameOrNamespace(name, source))
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
		checkAmbiguities(ret, name.getName() + "/" + name.getNamespaceUri(), source);
		return ret.isEmpty() ? Optional.empty() : Optional.of(ret.entrySet().iterator().next());
	}

	public static <T> Optional<Map.Entry<Definition, T>> findByNameOrNamespace(String name, String source,
			Map<Definition, T> definitions) {
		var ret = definitions.entrySet()
				.stream()
				.filter(e -> e.getKey().equalsByNameOrNamespace(name, source))
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
		checkAmbiguities(ret, name, source);
		return ret.isEmpty() ? Optional.empty() : Optional.of(ret.entrySet().iterator().next());
	}

	public static <T> Optional<Map.Entry<AttributeName, T>> findAttributeByNameOrNamespace(String name, String source,
			Map<AttributeName, T> definitions) {
		var ret = definitions.entrySet()
				.stream()
				.filter(e -> e.getKey().equalsByNameOrNamespace(name, source))
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
		checkAmbiguities(ret, name, source);
		return ret.isEmpty() ? Optional.empty() : Optional.of(ret.entrySet().iterator().next());
	}

	public static Map<AttributeName, List<String>> findAllByNameOrNamespace(String name, String source,
			Map<? extends AttributeName, List<String>> attributes) {
		return attributes.entrySet()
				.stream()
				.filter(e -> e.getKey().equalsByNameOrNamespace(name, source))
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
	}

	public static Map<AttributeName, List<String>> findAllByNameOrNamespace(AttributeName name, String source,
			Map<? extends AttributeName, List<String>> attributes) {
		return attributes.entrySet()
				.stream()
				.filter(e -> e.getKey().equalsByNameOrNamespace(name, source))
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
	}

	public static <T> List<T> findListByNameOrNamespace(AttributeName name, Map<Definition, List<T>> definitions) {
		var entry = findByNameOrNamespace(name, null, definitions);
		return getList(entry);
	}

	public static <T> List<T> findListByNameOrNamespace(String name, Map<Definition, List<T>> definitions) {
		var entry = findByNameOrNamespace(name, null, definitions);
		return getList(entry);
	}

	public static <T> T findSingleValueByNameOrNamespace(AttributeName name, Map<Definition, List<T>> definitions) {
		var list = findListByNameOrNamespace(name, definitions);
		return getSingleValue(list, name);
	}

	public static <T> T findSingleValueByNameOrNamespace(String name, Map<Definition, List<T>> definitions) {
		var list = findListByNameOrNamespace(name, definitions);
		return getSingleValue(list, name);
	}

	public static <K extends AttributeName, T> List<T> getList(Optional<Map.Entry<K, List<T>>> entry) {
		return entry.isPresent() ? entry.get().getValue() : Collections.emptyList();
	}

	private static <K extends AttributeName, T> K getName(Optional<Map.Entry<K, T>> entry) {
		return entry.isPresent() ? entry.get().getKey() : null;
	}

	public static <T, K> T getSingleValue(List<T> list, K nameForTracing) {
		if (CollectionUtils.isEmpty(list)) {
			return null;
		}
		if (list.size() > 1) {
			log.info("Potential ambiguity: Picking first value for name={} from values={}", nameForTracing, list);
		}
		return list.get(0);
	}

	public static <K extends AttributeName, T> T getSingleValue(Optional<Map.Entry<K, List<T>>> entry) {
		var values = getList(entry);
		return getSingleValue(values, getName(entry));
	}

	public static <T> List<T> findCpAttributeListByNameOrNamespace(String name, Map<AttributeName, List<T>> definitions) {
		var entry = findAttributeByNameOrNamespace(name, null, definitions);
		return getList(entry);
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

	public static void mapCpAttributeList(Map<AttributeName, List<String>> attributes,
			Map<Definition, List<String>> definitions) {
		if (attributes == null) {
			return;
		}
		for (var attribute : attributes.entrySet()) {
			AttributeName attributeDefinition = attribute.getKey();
			var key = mapCpAttributeName(attributeDefinition.getName(), attributeDefinition.getNamespaceUri(),
					attributeDefinition.getSource());
			definitions.put(key, attribute.getValue());
		}
	}

	public static void mapAttributeList(Map<AttributeName, List<String>> attributes, Map<Definition, List<String>> definitions) {
		if (attributes == null) {
			return;
		}
		for (var attribute : attributes.entrySet()) {
			var key = mapCpAttributeName(attribute.getKey().getName(), attribute.getKey().getNamespaceUri(), null);
			if (key != null) {
				definitions.put(key, attribute.getValue());
			}
		}
	}

	private static Definition mapCpAttributeName(String name, String fqName, String source) {
		if (name == null && fqName == null) {
			return null;
		}
		return Definition.builder()
						 .name(name)
						 .namespaceUri(fqName)
						 .source(source)
						 .build();
	}

	// Restricted by design: Use to set sessionProfileExtId only
	public static void putAttributeDefinitionValue(Map<AttributeName, List<String>> attributes,
			String name, String fqName, String value) {
		var newValue = valueToList(value);
		var key = Definition.builder()
							.name(name)
							.namespaceUri(fqName)
							.source(null)
							.build();
		attributes.put(key, newValue);
	}

	// Restricted by design: Used by AfterIdm groovy scripting only
	public static void putDefinitionValue(Map<Definition, List<String>> attributes,
			String name, String fqName, AuditDto.AttributeSource source, String value) {
		var newValue = valueToList(value);
		var key = Definition.builder()
							.name(name)
							.namespaceUri(fqName)
							.source(source != null ? source.name() : null)
							.build();
		attributes.put(key, newValue);
	}

	public static void putAttributeValue(Map<AttributeName, List<String>> attributes, AttributeName attribute, String value) {
		var newValue = valueToList(value);
		var key = new Definition(attribute);
		attributes.put(key, newValue);
	}

	private static ArrayList<String> valueToList(String value) {
		var newValue = new ArrayList<String>(); // mutable, as addAttribute extends
		newValue.add(value != null ? value : VALUE_TO_LIST_NULL); // signal invalid null usage
		return newValue;
	}

	public static void putOrRemoveCpAttributeValues(Map<AttributeName, List<String>> attributes,
			String name, String fqName, String source, List<String> values) {
		var key = Definition.builder()
							.name(name)
							.namespaceUri(fqName)
							.source(source)
							.build();
		if (values == null) {
			attributes.remove(key);
		}
		else {
			attributes.put(key, values);
		}
	}

	public static void replaceAttributeValuesFromSource(Map<AttributeName, List<String>> attributes,
			String name, String fqName, List<String> values, String source) {
		// can have more values if we get IDM data from multiple source (multiple queries or profiles)
		var ret = findAllByNameOrNamespace(name, source, attributes);
		// should not happen
		if (ret.isEmpty()) {
			putOrRemoveCpAttributeValues(attributes, name, fqName, source, values);
			return;
		}
		if (values == null) {
			values = valueToList(null);
		}
		for (Map.Entry<AttributeName, List<String>> entry : ret.entrySet()) {
			// Replace only in the same source
			if (Objects.equals(entry.getKey().getSource(), source)) {
				attributes.remove(entry.getKey());
				putOrRemoveCpAttributeValues(attributes, name, fqName, entry.getKey().getSource(), values);
			}
		}
	}

	public static void applyProfileSelection(CpResponse cpResponse, ProfileSelectionResult psResult) {
		if (psResult != null) {
			var filteredAttributes = psResult.getFilteredAttributes();
			if (filteredAttributes.isPresent()) {
				Map<Definition, List<String>> responseAttrs = new HashMap<>();
				for (Map.Entry<AttributeName, List<String>> entry : filteredAttributes.get().entrySet()) {
					responseAttrs.put(new Definition(entry.getKey()), entry.getValue());
				}
				cpResponse.setUserDetails(responseAttrs);
			}
		}
	}

	public static void applyDeduplication(TrustBrokerProperties trustBrokerProperties, String destination,
			CpResponse cpResponse, RelyingParty relyingParty) {

		List<String> dropDuplicatedAttributes = Collections.emptyList();
		var dropDuplicatedAttributesConfig = trustBrokerProperties.getOidc().getDropDuplicatedAttributeFromOriginalIssuer();
		if (isXtbDestination(trustBrokerProperties, destination) && ArrayUtils.isNotEmpty(dropDuplicatedAttributesConfig)) {
			dropDuplicatedAttributes = Arrays.asList(dropDuplicatedAttributesConfig);
			log.debug("OIDC: Dropping original issuer version if duplicated for attributes={}", dropDuplicatedAttributes);
		}

		cpResponse.setUserDetails(deduplicatedRpAttributes(cpResponse.getUserDetails(), cpResponse.getProperties(),
				relyingParty.getConstAttributes()));
		cpResponse.setAttributes(deduplicatedCpAttributes(cpResponse, dropDuplicatedAttributes, relyingParty.getConstAttributes()));
	}

	public static Map<Definition, List<String>> deduplicatedRpAttributes(Map<Definition, List<String>> userDetailMap,
			Map<Definition, List<String>> properties, ConstAttributes constAttributes) {
		Map<Definition, List<String>> responseAttrs = new HashMap<>();
		for (Map.Entry<Definition, List<String>> entry : userDetailMap.entrySet()) {
			Definition key = entry.getKey();
			List<String> value = entry.getValue();
			// Result does not contain the Definition and Properties does not contains it
			if (!definitionInRpMaps(key, value, responseAttrs, properties, constAttributes)) {
				responseAttrs.put(key, value);
			}
		}
		return responseAttrs;
	}

	private static boolean constContainsDefinition(ConstAttributes constAttributes, Definition key, List<String> value) {
		if (constAttributes == null || constAttributes.getAttributeDefinitions() == null
				|| constAttributes.getAttributeDefinitions().isEmpty()) {
			return false;
		}
		for (Definition constDef : constAttributes.getAttributeDefinitions()) {
			if (definitionAndValueEquals(key, value, constDef, constDef.getValues())) {
				return true;
			}
		}
		return false;
	}

	private static boolean constContainsDefinition(ConstAttributes constAttributes, Definition key) {
		if (constAttributes == null || constAttributes.getAttributeDefinitions() == null
				|| constAttributes.getAttributeDefinitions().isEmpty()) {
			return false;
		}
		for (Definition constDef : constAttributes.getAttributeDefinitions()) {
			if (definitionEqualsNamespaceUriOrName(key, constDef)) {
				return true;
			}
		}
		return false;
	}

	public static Map<Definition, List<String>> deduplicatedCpAttributes(CpResponse cpResponse,
			List<String> dropDuplicatedAttributes, ConstAttributes constAttributes) {

		Map<Definition, List<String>> attributes = cpResponse.getAttributes();
		Map<Definition, List<String>> userDetails = cpResponse.getUserDetails();
		Map<Definition, List<String>> properties = cpResponse.getProperties();

		Map<Definition, List<String>> responseAttrs = new HashMap<>();
		for (Map.Entry<Definition, List<String>> entry : attributes.entrySet()) {
			Definition key = entry.getKey();
			List<String> value = entry.getValue();
			if (mapContainsDefinitionWithValue(responseAttrs, key, value)
					|| attributeToDrop(key, dropDuplicatedAttributes, userDetails, properties, constAttributes)) {
				log.debug("Dropping duplicated attribute={} from original issuer in list={}", key, dropDuplicatedAttributes);
			}
			else {
				responseAttrs.put(key, value);
			}
		}

		return responseAttrs;
	}

	static boolean attributeToDrop(Definition definition, List<String> attributesToBeDropped,
			Map<Definition, List<String>> userDetails, Map<Definition, List<String>> properties,
			ConstAttributes constAttributes) {
		if (CollectionUtils.isEmpty(attributesToBeDropped)) {
			return false;
		}
		var attributeToDrop = definition.getNamespaceUri() != null ? definition.getNamespaceUri() : definition.getName();
		// Check if attribute should be dropped
		if (attributeToDrop != null && attributesToBeDropped.contains(attributeToDrop)) {
			// Drop if the Definition is in userDetails, properties or constants
			return definitionInRpMaps(definition, userDetails, properties, constAttributes);
		}
		return false;
	}

	private static boolean definitionInRpMaps(Definition definition,
			Map<Definition, List<String>> userDetails, Map<Definition, List<String>> properties,
			ConstAttributes constAttributes) {
		return mapContainsDefinitionWithValue(userDetails, definition) || mapContainsDefinitionWithValue(properties, definition)
				|| constContainsDefinition(constAttributes, definition);
	}

	private static boolean definitionInRpMaps(Definition definition, List<String> values,
			Map<Definition, List<String>> userDetails, Map<Definition, List<String>> properties,
			ConstAttributes constAttributes) {
		return mapContainsDefinitionWithValue(userDetails, definition, values)
				|| mapContainsDefinitionWithValue(properties, definition, values)
				|| constContainsDefinition(constAttributes, definition, values);
	}

	static boolean mapContainsDefinitionWithValue(Map<Definition, List<String>> attributes, Definition definition,
			List<String> values) {
		for (Map.Entry<Definition, List<String>> entry : attributes.entrySet()){
			Definition attrDef = entry.getKey();
			List<String> attrValue = entry.getValue();
			if (definitionAndValueEquals(definition, values, attrDef, attrValue)) {
				return true;
			}
		}
		return false;
	}

	private static boolean mapContainsDefinitionWithValue(Map<Definition, List<String>> attributes, Definition definition) {
		for (Map.Entry<Definition, List<String>> entry : attributes.entrySet()) {
			Definition attrDef = entry.getKey();
			if (definitionEqualsNamespaceUriOrName(definition, attrDef)) {
				return true;
			}
		}
		return false;
	}

	static boolean definitionEqualsNamespaceUriOrName(Definition def1, Definition def2) {
		if (def1.getNamespaceUri() != null && def2.getNamespaceUri() != null) {
			return def1.getNamespaceUri().equals(def2.getNamespaceUri());
		}
		else if (def1.getName() != null && def2.getName() != null) {
			return def1.getName().equals(def2.getName());
		}
		return false;
	}

	static boolean definitionAndValueEquals(Definition def1, List<String> values1, Definition def2,
			List<String> values2) {
		return definitionEqualsNamespaceUriOrName(def1, def2) && listMatch(values1, values2);
	}

	static boolean listMatch(List<String> values, List<String> resultValues) {
		if (values == null || resultValues == null) {
			return resultValues == values;
		}

		return CollectionUtils.isEqualCollection(values, resultValues);
	}

	public static boolean isXtbDestination(TrustBrokerProperties trustBrokerProperties, String destination) {
		if (destination == null || trustBrokerProperties.getOidc().getPerimeterUrl() == null) {
			return false;
		}
		try {
			URI destinationUrl = new URI(destination);
			URI oidcPerimeterUrl = new URI(trustBrokerProperties.getOidc().getPerimeterUrl());
			if (destinationUrl.getHost() == null || oidcPerimeterUrl.getHost() == null) {
				return false;
			}
			return destinationUrl.getHost().equals(oidcPerimeterUrl.getHost());
		}
		catch (URISyntaxException ex) {
			throw new RequestDeniedException("Invalid URL", ex);
		}
	}

	public static void applyConfigFilter(CpResponse cpResponse, RelyingPartySetupService relyingPartySetupService,
			ResponseParameters params, RelyingParty relyingParty) {

		// filter CP attributes on relying party side (CP side already done)
		var idpAttributesDefinition = RelyingPartySetupUtil.getIdpAttrDefinitions(cpResponse, relyingPartySetupService, params);
		cpResponse.setAttributes(filterAndCreateCpDefinitions(cpResponse.getAttributes(), idpAttributesDefinition));

		// Apply RP config filter
		cpResponse.setUserDetails(AttributeFilterUtil.filteredUserDetails(cpResponse.getUserDetails(), relyingParty.getIdmLookup()));

		// Apply final Property selection (properties set in script but not in config must be filtered out)
		cpResponse.setProperties(AttributeFilterUtil.filterProperties(cpResponse.getProperties(), relyingParty.getPropertiesSelection()));
	}

	static Map<Definition, List<String>> filterAndCreateCpDefinitions(Map<Definition, List<String>> attributes,
			Collection<Definition> confAttributes) {
		if (attributes == null) {
			throw new TechnicalException("Missing IDP response attributes");
		}
		Map<Definition, List<String>> respIdpAttributes = new HashMap<>();
		for (Definition definition : confAttributes) {
			var attributeValues = getAttributeValues(attributes, definition);
			if (!attributeValues.isEmpty()) {
				var newDefinition = definition.toBuilder().values(attributeValues).build();
				respIdpAttributes.put(newDefinition,  attributeValues);
			}
		}
		return respIdpAttributes;
	}

	private static List<String> getAttributeValues(Map<Definition, List<String>> userDetails, Definition definition) {
		return userDetails.entrySet()
				.stream()
				.filter(userAttribute -> userAttribute.getKey().equalsByNameOrNamespace(definition))
				.map(Map.Entry::getValue)
				.findFirst() // CP attributes are unique within CP source
				.orElse(Collections.emptyList());

	}

	/**
	 * First value matching namespace or as fallback, matching name and has a namespace
	 * (i.e. attribute with a same name but differing namespace).
	 */
	public static List<String> findValueByNamespaceUriOrName(Map<? extends AttributeName, List<String>> attributes,
			AttributeName attributeName) {
		for (var entry : attributes.entrySet()) {
			var attrDef = entry.getKey();
			if (attributeName.equalsByNamespace(attrDef)) {
				return entry.getValue();
			}
		}
		// fallback
		for (var entry : attributes.entrySet()) {
			var attrDef = entry.getKey();
			if (attrDef.getNamespaceUri() != null && attributeName.equalsByName(attrDef)) {
				return entry.getValue();
			}
		}
		return Collections.emptyList();
	}

	private static void checkAmbiguities(Map<? extends AttributeName, ?> result, String name, String source) {
		if (result.size() > 1) {
			var availableSources = result.keySet().stream()
					.filter(k -> source == null || k.getSource().equals(source))
					.map(k -> k.getSource())
					.toList();
			log.warn("Ambiguous access to attributeName={} source={} (HINT: Add one of availableSources='{}' to clarify)",
					name, source, availableSources);
		}
	}

}
