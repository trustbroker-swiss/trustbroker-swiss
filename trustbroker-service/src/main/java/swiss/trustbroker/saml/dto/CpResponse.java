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

package swiss.trustbroker.saml.dto;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.CollectionUtils;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;
import swiss.trustbroker.api.sessioncache.dto.CpResponseData;
import swiss.trustbroker.audit.dto.AuditDto;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.util.CollectionUtil;
import swiss.trustbroker.common.util.JsonUtil;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.IdmLookup;
import swiss.trustbroker.federation.xmlconfig.IdmQuery;
import swiss.trustbroker.homerealmdiscovery.util.DefinitionUtil;

/**
 * This class implement the processing context which is the core of the XTB processing model according.
 * The context is mapped from CP SAML response and/or stored as session state.
 * Note that original attributes should not be used in scripting except may be for read-only debugging.
 */
@Data
@EqualsAndHashCode(callSuper=false)
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
@Slf4j
public class CpResponse extends ResponseStatus implements CpResponseData {

	// CP SAML response extracted fields for easier handling in code and scripts

	private String inResponseTo;

	private String nameId;

	private String originalNameId; // CP Response incoming subject used for internal processing

	private String nameIdFormat;

	private String subjectConfirmationMethod;

	private String authStateInstant;

	private List<String> contextClasses;

	private String issuer;// CP Response issuer also referred to as HomeRealm

	private String homeName; // HomeName used by IdmService to query IDM

	private String destination; // AuthnRequest.AssertionConsumerUrl from our AuthnRequest

	private String authLevel; // declared QoA CP side

	// RP initiated SAML authnrequest data

	private String rpIssuer; // incoming SAML issuer on RP side

	private String rpReferer; // incoming HTTP referrer on RP side

	private List<String> rpContextClasses; // incoming context class requirements on RP side

	private String rpDestination; // override SAML Response.Destination on RP side

	private String rpRecipient; // override SAML SubjectConfirmationData.Recipient on RP side

	private String clientExtId; // retrieved IDM primary reference for internal reference

	private String clientName; // RelyingParty <ClientName> as used in the IDM credential SAML-Federation Issuer NameID

	private String applicationName; // RP/OIDC context sending 'SAML clientId' in ProviderName

	// OIDC context only

	private String oidcClientId; // incoming client_id

	private Set<String> oidcScopes; // incoming scopes

	// internal script processing

	private String customIssuer; // override RP response issuer

	/**
	 The HttpServletRequest params, some specific ones: username, Client_Network
	 */
	@Builder.Default
	private Map<String, String> rpContext = new HashMap<>();

	/**
	 * The attributes map contains these attributes:
	 * <ul>
	 * <li>CP SAML Response attributes extracted from the message</li>
	 * <li>Derived attributes computed in ScriptService BeforeIdm hooks</li>
	 * </ul>
	 * The names in this map are usually fully qualified as represented in the SAML response from the CP. This map is logged by
	 * the AuditService when SAML response comes in from CP.
	 */
	@Builder.Default
	private Map<Definition, List<String>> attributes = new HashMap<>();

	/**
	 * Copy of Attributes before filtering. Necessary for SSO
	 */
	@Builder.Default
	private Map<Definition, List<String>> originalAttributes = new HashMap<>();

	/**
	 * Contains the idmLookup for the corresponding RP The Query list can be from Groovy scripts
	 */
	private IdmLookup idmLookup;

	/**
	 * IDM user data returned from IDM backends, filtered by RP setup.
	 */
	@Builder.Default
	@JsonSerialize(keyUsing = DefinitionSerializer.class)
	@JsonProperty("userDetails")
	@JsonDeserialize(keyUsing = DefinitionDeserializer.class)
	private Map<Definition, List<String>> userDetails = new HashMap<>();

	private int originalUserDetailsCount;

	/**
	 * Properties contain computed values that can be sent as RP attributes based on incoming CP attributes and userdetails.
	 * They are selected by the <PropertiesSelection/> configuration.
	 */
	@Builder.Default
	@JsonSerialize(keyUsing = DefinitionSerializer.class)
	@JsonProperty("properties")
	@JsonDeserialize(keyUsing = DefinitionDeserializer.class)
	private Map<Definition, List<String>> properties = new HashMap<>();

	private int originalPropertiesCount;

	/**
	 * The results map contains these SAML attributes:
	 * <ul>
	 * <li>CP SAML Response attributes extracted from the message (PassThrough Claims from CP)</li>
	 * <li>Derived attributes computed in ScriptService BeforeIdm hooks (Computed CP claims)</li>
	 * <li>IDM attributes retrieved from the IDMService</li>
	 * <li>Derived attributes computed in ScriptService AfterIdm hooks (Computed IDM claims)</li>
	 * </ul>
	 * The names in this map are usually fully qualified as represented in the SAML response from the CP. This map is logged by
	 * the AuditService when SAML response is sent to RP.
	 * Type system in SAML: Strings and List>String> only.
	 * Results are used for auditing only at the time being.
	 */
	@Builder.Default
	private Map<Definition, List<String>> results = new HashMap<>();

	/**
	 * The claims map contains these OIDC claims:
	 * <ul>
	 * <li>Everything that was annotated with an oidcName in the configuration.</li>
	 * <li>All well known OIDC claims of the openid scope declared in AttributeName (StandardClaims).</li>
	 * <li>Everything added or removed in a OIDC OnToken groovy script hook.</li>
	 * </ul>
	 * We use Object values because of nested collection support.
	 * Type system in SAML: Any object that supports JSONAware (json serialization) or a toString conversion otherwise.
	 * Claims are used for OIDC token generation as opposed to results (different type system).
	 */
	@Builder.Default
	private transient Map<String, Object> claims = new HashMap<>();

	// better API for groovy scripts

	@Override
	public List<String> getAttributes(String name) {
		var ret = findAttributesInMap(name, attributes);
		return ret == null ? Collections.emptyList() : ret;
	}

	@Override
	public String getAttribute(String name) {
		var ret = findAttributesInMap(name, attributes);
		return CollectionUtils.firstElement(ret);
	}

	public void setAttribute(String name, String value) {
		if (name == null || value == null) {
			log.warn("CpResponse.setAttribute(name={}, value={}) rejected", name, value);
			return;
		}
		var newValue = new ArrayList<>(List.of(value)); // mutable, as addAttribute extends
		setAttributes(name, newValue);
	}

	public void setAttributes(String name, List<String> values) {
		if (name == null || values == null || values.isEmpty()) {
			log.warn("CpResponse.setAttributes(name={}, values={}) rejected", name, values);
			return;
		}
		var oldValue = attributes.put(new Definition(name), values);
		log.debug("CpResponse.attribute change name={} value={} oldValue={}", name, values, oldValue);
	}

	// script hook: add value or create entry
	public void addAttribute(String name, String value) {
		if (name == null || value == null) {
			log.warn("CpResponse.addAttribute(name={}, value={}) rejected", name, value);
			return;
		}
		var oldValues = getAttributes(name);
		var newValues = new ArrayList<String>();
		if (oldValues != null) {
			newValues.addAll(oldValues);
		}
		newValues.add(value);
		setAttributes(name, newValues);
	}

	public void removeAttributes(String name) {
		removeAttributeFromMap(name, null, attributes);
	}

	// script hook use: get all values using name or FQ name
	@Override
	public List<String> getUserDetails(String name) {
		return getUserDetails(name, null);
	}

	// script hook use: get first value using name or FQ name
	@Override
	public String getUserDetail(String name) {
		return getUserDetail(name, null);
	}

	@Override
	public List<String> getUserDetails(String name, String source) {
		var ret = DefinitionUtil.findAllByNameOrNamespace(name, source, userDetails);
		var definitionValue = ret.entrySet()
				.stream()
				.findFirst();
		return definitionValue.map(Map.Entry::getValue)
							  .orElse(null); // empty list would be nicer, but we have scripts using this
	}

	@Override
	public String getUserDetail(String name, String source) {
		var details = getUserDetails(name, source);
		return DefinitionUtil.getSingleValue(details, name);
	}

	// script hook use: remove entry by name or FQ name
	public List<String> removeUserDetails(String name) {
		return removeUserDetails(name, null);
	}

	public List<String> removeUserDetails(String name, String source) {
		return removeAttributeFromMap(name, source, userDetails);
	}

	// script hook use: add entry with a single value
	public void setUserDetail(String name, String fqName, String value) {
		if ((name == null && fqName == null) || value == null) {
			log.warn("CpResponse.setUserDetail(name={}, fqName={}, values={}) rejected", name, fqName, value);
			return;
		}
		removeUserDetails(name != null ? name : fqName, null); // switch source to script
		DefinitionUtil.putDefinitionValue(userDetails, name, fqName, AuditDto.AttributeSource.SCRIPT, value);
	}

	// script hook: add value or create entry
	public void addUserDetail(String name, String fqName, String value) {
		addUserDetail(name, fqName, value, null);
	}

	public void addUserDetail(String name, String fqName, String value, String source) {
		if ((name == null && fqName == null) || value == null) {
			log.warn("CpResponse.addUserDetail(name={}, fqName={}, values={}) rejected", name, fqName, value);
			return;
		}
		var ret = DefinitionUtil.findByNameOrNamespace(name, source, userDetails);
		if (ret.isPresent()) {
			var values = new ArrayList<>(ret.get().getValue());
			values.add(value);
			setUserDetails(name, fqName, values);
		}
		else {
			setUserDetail(name, fqName, value);
		}
	}

	public boolean addUserDetailIfMissing(String name, String fqName, String value) {
		var ret = DefinitionUtil.findByNameOrNamespace(name, null, userDetails);
		if (ret.isEmpty()) {
			setUserDetail(name, fqName, value);
			return true;
		}
		return false;
	}

	// script hook use: add entry with a list value
	public void setUserDetails(String name, String fqName, List<String> values) {
		if ((name == null && fqName == null) || values == null || values.isEmpty()) {
			log.warn("CpResponse.setUserDetails(name={}, fqName={}, values={}) rejected", name, fqName, values);
			return;
		}
		removeUserDetails(name != null ? name : fqName, null); // switch source to script
		userDetails.put(Definition.builder()
								  .name(name)
								  .namespaceUri(fqName)
								  .source(AuditDto.AttributeSource.SCRIPT.name())
								  .build(), values);
	}

	public void setResult(Definition definition, List<String> values) {
		if (values == null) {
			values = new ArrayList<>(); // mutable
		}
		var oldValues = results.put(definition, values);
		log.debug("Set result definition='{}' oldValues='{}'", definition, oldValues);
	}

	public void skipQuery(String typeOrId) {
		List<IdmQuery> idmQueries = idmLookup.getQueries()
				.stream()
				.filter(idmQuery -> {
					var idMatch = idmQuery.getId() != null && idmQuery.getId().equals(typeOrId);
					var nameMatch = idmQuery.getId() == null  &&
							idmQuery.getName() != null && idmQuery.getName().equals(typeOrId);
					return idMatch || nameMatch;
				}).toList();
		if (idmQueries.size() > 1) {
			throw new TechnicalException(String.format("Query with typeOrId=%s is not unique, please set an id", typeOrId));
		}
		if (idmQueries.isEmpty()) {
			throw new TechnicalException(String.format("Query with typeOrId=%s was not found", typeOrId));
		}
		idmLookup.getQueries().remove(idmQueries.get(0));
	}

	// script hook use: get all values using name or FQ name
	@Override
	public List<String> getProperties(String name) {
		return findAttributesInMap(name, properties);
	}

	// script hook use: get first value using name or FQ name
	@Override
	public String getProperty(String name) {
		var ret = DefinitionUtil.findByNameOrNamespace(name, null, properties);
		return ret.isEmpty() || ret.get().getValue() == null || ret.get().getValue().isEmpty() ?
				null : ret.get().getValue().get(0);
	}

	// script hook use: remove entry by name or FQ name
	public List<String> removeProperty(String name) {
		return removeAttributeFromMap(name, null, properties);
	}

	// script hook use: add entry with a list value
	public void setProperties(String name, String fqName, List<String> values) {
		if ((name == null && fqName == null) || values == null || values.isEmpty()) {
			log.warn("CpResponse.setProperties(name={}, fqName={}, values={}) rejected", name, fqName, values);
			return;
		}
		properties.put(Definition.builder().name(name).namespaceUri(fqName).build(), values);
	}

	// script hook use: add entry with a single value
	public void setProperty(String name, String fqName, String value) {
		if ((name == null && fqName == null) || value == null) {
			log.warn("CpResponse.setProperty(name={}, fqName={}, values={}) rejected", name, fqName, value);
			return;
		}
		// prevent NPE when a script does not null check
		var newValue = new ArrayList<String>(); // mutable, as addAttribute extends
		newValue.add(value);
		properties.put(Definition.builder().name(name).namespaceUri(fqName).build(), newValue);
	}

	public boolean addPropertyIfMissing(String name, String fqName, String value) {
		var ret = DefinitionUtil.findByNameOrNamespace(name, null, properties);
		if (ret.isEmpty()) {
			setProperty(name, fqName, value);
			return true;
		}
		return false;
	}

	// script hook use: add value to an already available list value or create
	public void addProperty(String name, String fqName, String value) {
		if ((name == null && fqName == null) || value == null) {
			log.warn("CpResponse.addProperty(name={}, fqName={}, values={}) rejected", name, fqName, value);
			return;
		}
		addProperties(name, fqName, new ArrayList<>(List.of(value)));
	}

	// script hook use: add values to an already available list value or create
	public void addProperties(String name, String fqName, List<String> values) {
		if (name == null || values == null || values.isEmpty()) {
			log.warn("CpResponse.addProperty(name={}, values={}) rejected", name, values);
			return;
		}
		var ret = DefinitionUtil.findByNameOrNamespace(name, null, properties);
		if (ret.isPresent()) {
			values = CollectionUtil.addToListIfNotExist(ret.get().getValue(), values);
		}
		log.debug("Adding properties with name={} and values={}", name, values);
		setProperties(name, fqName, values);
	}

	public Object getClaims(String name) {
		var ret = claims != null ? claims.get(name) : null;
		return ret == null ? Collections.emptyList() : ret;
	}

	// converts values to (possibly immutable) list if needed, empty list for null
	public List<Object> getClaimList(String name) {
		var ret = claims != null ? claims.get(name) : null;
		return CollectionUtil.asList(ret);
	}

	public Object getClaim(String name) {
		var ret = claims != null ? claims.get(name) : null;
		return ret instanceof List<?> list ? CollectionUtils.firstElement(list) : ret;
	}

	public void setClaim(String name, Object value) {
		if (name == null || value == null || (value instanceof Collection<?> col && col.isEmpty())) {
			log.warn("CpResponse.setClaim(name={}, value={}) rejected", name, value);
			return;
		}
		var oldValue = claims.put(name, value);
		log.debug("CpResponse.claims change name={} value={} oldValue={}", name, value, oldValue);
	}

	public void setJsonClaim(String name, Object value) {
		var newValue = new ArrayList<>();
		if (value instanceof Collection<?> col) {
			newValue.addAll(col);
		}
		else {
			newValue.add(value);
		}
		setClaim(name, newValue); // override
	}

	public void setClaims(String name, Object values) {
		setClaim(name, values);
	}

	// converts values to (possibly immutable) list if needed, empty list for null
	public void setClaimList(String name, Object values) {
		setClaim(name, CollectionUtil.asList(values));
	}

	public void setJsonClaims(String name, Object values) {
		setJsonClaim(name, values);
	}

	private void addClaim(String parent, String name, Object value) {
		if (name == null || value == null) {
			log.warn("CpResponse.addClaim(parent={}, name={}, value={}) rejected", parent, name, value);
			return;
		}
		var claimKey = parent == null ? name : parent;
		var oldValue = getClaims(claimKey);
		// struct (handle as Map)
		if (parent != null) {
			var newValue = new LinkedHashMap<>();
			if (oldValue != null) {
				newValue.putAll(CollectionUtil.asMap(name, value, oldValue));
			}
			newValue.put(name, value); // appendField on JSONObject
			setClaim(claimKey, newValue);
			return;
		}
		// array (list handling => also for single values)
		var newValue = new ArrayList<>();
		if (oldValue != null) {
			newValue.addAll(CollectionUtil.asCollection(oldValue));
		}
		newValue.addAll(CollectionUtil.asCollection(value));
		setClaim(claimKey, newValue);
	}

	public void addClaim(String name, Object value) {
		addClaim(null, name, value);
	}

	public void addJsonClaim(String name, Object value) {
		addClaim(null, name, value);
	}

	public void addJsonClaim(String parent, String name, Object value) {
		addClaim(parent, name, value);
	}

	public void setParsedJsonAsClaim(String name, String value) {
		var newValue = JsonUtil.parseJson(value, false);
		setClaim(name, newValue);
	}

	public void addParsedJsonAsClaim(String parent, String name, String value) {
		var newValue = JsonUtil.parseJson(value, false);
		addClaim(parent, name, newValue);
	}

	public void removeClaim(String name) {
		var oldValue = claims.remove(name);
		log.debug("CpResponse.claims remove name={} oldValue={}", name, oldValue);
	}

	// private internal methods not to be used by scripts directly

	private static List<String> findAttributesInMap(String name, Map<Definition, List<String>> map) {
		var ret = DefinitionUtil.findByNameOrNamespace(name, null, map); // source only attributes for now
		return ret.map(Map.Entry::getValue).orElse(null);
	}

	private static List<String> removeAttributeFromMap(String name, String source, Map<Definition, List<String>> map) {
		var nvPairs = DefinitionUtil.findAllByNameOrNamespace(name, source, map);
		var ret = new ArrayList<String>();
		nvPairs.forEach((k, v) -> ret.addAll(map.remove(k)));
		return ret;
	}

	@JsonIgnore
	@Override
	public String getIssuerId() {
		return getIssuer();
	}

	@JsonIgnore
	@Override
	public Map<AttributeName, List<String>> getAttributeMap() {
		return Collections.unmodifiableMap(attributes);
	}

	@JsonIgnore
	@Override
	public Map<AttributeName, List<String>> getPropertyMap() {
		return Collections.unmodifiableMap(properties);
	}

	@JsonIgnore
	@Override
	public Map<AttributeName, List<String>> getUserDetailMap() {
		Map<AttributeName, List<String>> result = new HashMap<>();
		for (Map.Entry<Definition, List<String>> entry : userDetails.entrySet()) {
			var key = entry.getKey();
			result.put(Definition.builder()
								 .name(key.getName())
								 .namespaceUri(key.getNamespaceUri())
								 .source(key.getSource())
								 .build(),
					entry.getValue());
		}
		return Collections.unmodifiableMap(result);
	}

	@JsonIgnore
	public boolean hasOriginalNameId() {
		return originalNameId != null && originalNameId.equals(nameId);
	}

}
