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

import java.io.Serializable;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonKey;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import org.springframework.util.CollectionUtils;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;
import swiss.trustbroker.common.saml.util.AttributeRegistry;

/**
 * Attribute definition.
 *
 * For custom attributes see AttributeInitializer.
 *
 * @see swiss.trustbroker.api.sessioncache.service.AttributeInitializer
 */
@XmlRootElement(name = "Definition")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@EqualsAndHashCode(of = { "name", "namespaceUri", "source" }) // oidcName is derived only and does not need to be in key
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
public class Definition implements Serializable, AttributeName {

	private static final String CLAIM_NAME_DELIMITER = ",";

	/**
	 * 	Short name used in auditing and for IDM attribute addressing.
 	 */
	@XmlAttribute(name = "name")
	@JsonKey // needed for Jackson serialization as Map key
	// So far we only use Definition as Map key in CpResponse and only with a name (no namespaceUri), so this is sufficient
	// If we need both, we need to implement a proper JsonSerializer, see:
	// https://www.baeldung.com/jackson-map
	private String name;

	/**
	 * 	Known external attributes we just document here - used when we cannot use namespaceUri due to semantics.
 	 */
	@XmlAttribute(name = "altName")
	private String altName;

	/**
	 * The long name is used in the generated SAML assertion towards the RP.
 	 */
	@XmlAttribute(name = "namespaceUri")
	private String namespaceUri;

	/**
	 * The claim names used when emitting an attribute to an OIDC client (comma-separated -
	 * as an attribute, it cannot be a List).
	 *
	 * @see Definition#oidcNamesToList(String)
	 * @see Definition#oidcNameListToString(List)
 	 */
	@XmlAttribute(name = "oidcNames")
	private String oidcNames;

	/**
	 * Indicates whether this field is considered CID (client identifying data).
	 * <br/>
	 * Default: null - global default is used
	 *
	 * @since 1.8.0
	 */
	@XmlAttribute(name = "cid")
	private Boolean cid;

	/**
	 * Multi value handling.
	 * <br/>
	 * Default: ORIGINAL
	 */
	@XmlAttribute(name = "multiValued")
	@Builder.Default
	private Multivalued multiValued = Multivalued.ORIGINAL;

	/**
	 * Mapper to be used for the value.
	 */
	@XmlAttribute(name = "oidcMapper")
	private OidcMapper oidcMapper;

	/**
	 * Single value from constant configuration (we currently only use single valued in XML via ConstAttributes).
 	 */
	@XmlAttribute(name = "value")
	private String value;

	/**
	 * Multiple values from CP input (multi valued possible in rare cases) - not used in XML.
 	 */
	@XmlTransient
	private List<String> values;

	/**
	 * To restrict emitting an attribute, the scope can be set as follows:
	 * <ul>
	 *     <li>saml: Use only in SAML assertions</li>
	 *     <li>oidc: Use only in OIDC tokens (oidcName must be set)</li>
	 * </ul>
	 * If not set, the attribute is emitted on all protocols and any requested OIDC scope.
 	 */
	@XmlAttribute(name = "scope")
	private String scope;

	/**
	 * Source of the definition
	 */
	@XmlTransient
	private String source;

	public Definition(String name) {
		this.name = name;
	}

	public Definition(String name, String namespaceUri) {
		this.name = name;
		this.namespaceUri = namespaceUri;
	}

	public Definition(AttributeName attributeName) {
		this.name = attributeName.getName();
		this.namespaceUri = attributeName.getNamespaceUri();
		this.altName = attributeName.getAltName();
		this.oidcNames = oidcNameListToString(attributeName.getOidcNameList());
		this.cid = attributeName.getCid();
		this.source = attributeName.getSource();
	}

	public Definition(String name, String namespaceUri, String singleValue) {
		this.name = name;
		this.namespaceUri = namespaceUri;
		this.value = singleValue;
	}

	public Definition(String name, String namespaceUri, List<String> multiValue) {
		this.name = name;
		this.namespaceUri = namespaceUri;
		this.values = multiValue;
	}

	public static Definition ofName(AttributeName attributeName) {
		return new Definition(attributeName.getName());
	}

	public static Definition ofNames(AttributeName attributeName) {
		return new Definition(attributeName.getName(), attributeName.getNamespaceUri());
	}

	public static Definition ofNamespaceUri(AttributeName attributeName) {
		return new Definition(attributeName.getNamespaceUri());
	}

	private static String oidcNameListToString(List<String> oidcNameList) {
		return CollectionUtils.isEmpty(oidcNameList) ? null : oidcNameList.stream().collect(Collectors.joining(", "));
	}

	private static List<String> oidcNamesToList(String oidcNames) {
		return oidcNames != null ? Arrays.asList(oidcNames.split(CLAIM_NAME_DELIMITER)) : Collections.emptyList();
	}

	public boolean hasNamedValues() {
		return namespaceUri != null && (value != null ||
				(values != null && !values.isEmpty()));
	}

	@Override
	@JsonIgnore
	public List<String> getOidcNameList() {
		return oidcNamesToList(oidcNames);
	}

	public List<String> getMultiValues() {
		if (value != null) {
			return List.of(value); // from config
		}
		return values != null ? values : Collections.emptyList(); // from CP
	}

	public AttributeName findAttributeName() {
		AttributeName attributeName = null;
		if (namespaceUri != null) {
			attributeName = AttributeRegistry.forName(namespaceUri);
		}
		if (attributeName == null && name != null) {
			attributeName = AttributeRegistry.forName(name);
		}
		return attributeName;
	}

	// true for all matching combinations of name and namespaceUri, false for nulls
	// (temporary Definition objects may have only a name containing a name or namespaceUri)
	@Override
	public boolean equalsByNameOrNamespace(AttributeName attributeName, String source) {
		if (attributeName == null) {
			return false;
		}
		var ret = false;
		if (name != null && namespaceUri != null) {
			ret = name.equals(attributeName.getName()) || name.equals(attributeName.getNamespaceUri()) ||
					namespaceUri.equals(attributeName.getNamespaceUri()) || namespaceUri.equals(attributeName.getName());
		}
		else if (namespaceUri != null) {
			ret = namespaceUri.equals(attributeName.getName()) || namespaceUri.equals(attributeName.getNamespaceUri());
		}
		else if (name != null) {
			ret = name.equals(attributeName.getName()) || name.equals(attributeName.getNamespaceUri());
		}
		return ret && (source == null || source.equals(getSource()));
	}

}
