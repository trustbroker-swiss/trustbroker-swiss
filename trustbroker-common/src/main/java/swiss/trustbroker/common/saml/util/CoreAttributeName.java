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

package swiss.trustbroker.common.saml.util;

import java.util.List;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;

/**
 * Standard attribute names and additional ones used by XTB.
 * <br/>
 * NOTE: This enum is mutable - fields other than name and functional can be updated based on configuration during
 * initialization.
 */
@Getter
@ToString
@AllArgsConstructor(access = AccessLevel.PACKAGE)
public enum CoreAttributeName implements MutableAttributeName {

	CLAIMS_NAME("ClaimsName", false,
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
			null, null),

	NAME_ID("NameId", true,
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
			null, null),

	EMAIL("EMail", true,
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
			null, List.of(StandardClaimNames.EMAIL)),

	FIRST_NAME("FirstName", true, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
			null, List.of(StandardClaimNames.GIVEN_NAME)),

	NAME("Name", true,
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
			null, List.of(StandardClaimNames.FAMILY_NAME)),

	ISSUED_CLIENT_EXT_ID("IssuedClientExtId", true, null, null, null),

	// Related to IDM SAML federation credential mappings in Default tenant towards access tenants
	HOME_NAME("HomeName", true,null,null, null),

	HOME_REALM("HomeRealm", true,null,null, null),

	AUTH_LEVEL("AuthLevel", false,null,null, null),

	// new session tracking feature
	SSO_SESSION_ID("SsoSessionId", true,null,null, null);

	private final String name;

	private final boolean functional;

	private String namespaceUri;

	private String altName;

	private List<String> oidcNameList;

	// the setters could be package-private for AttributeRegistry,
	// but they are inherited from the interface, so they must be public

	@Override
	@SuppressWarnings("java:S3066") // setter only used by AttributeRegistry during config initialization
	public void setNamespaceUri(String namespaceUri) {
		this.namespaceUri = namespaceUri;
	}

	@Override
	@SuppressWarnings("java:S3066") // setter only used by AttributeRegistry during config initialization
	public void setAltName(String altName) {
		this.altName = altName;
	}

	@Override
	@SuppressWarnings("java:S3066") // setter only used by AttributeRegistry during config initialization
	public void setOidcNameList(List<String> oidcNameList) {
		this.oidcNameList = oidcNameList;
	}

}
