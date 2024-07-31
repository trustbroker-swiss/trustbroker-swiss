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

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlRootElement;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import swiss.trustbroker.common.util.WebUtil;

/**
 * Security policy overrides for OIDC.
 */
@XmlRootElement(name = "OidcSecurityPolicies")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OidcSecurityPolicies implements Serializable {

	/**
	 * Require Proof Key for Code Exchange (PKCE).
	 * <br/>
	 * Default: true
	 */
	@XmlAttribute(name = "requireProofKey")
	@Builder.Default
	private Boolean requireProofKey = Boolean.TRUE;

	/**
	 * Require authorization consent (currently unsupported).
	 * <br/>
	 * Default: false
	 */
	@XmlAttribute(name = "requireAuthorizationConsent")
	@Builder.Default
	private Boolean requireAuthorizationConsent = Boolean.FALSE;

	/**
	 * Token valitity in minutes.
	 */
	@XmlAttribute(name = "tokenTimeToLiveMin")
	private Integer tokenTimeToLiveMin;

	/**
	 * Overrides tokenTimeToLiveMin for the access token.
 	 */
	@XmlAttribute(name = "accessTokenTimeToLiveMin")
	private Integer accessTokenTimeToLiveMin;

	/**
	 * Overrides tokenTimeToLiveMin for the ID token.
 	 */
	@XmlAttribute(name = "idTokenTimeToLiveMin")
	private Integer idTokenTimeToLiveMin;

	/**
	 * Overrides tokenTimeToLiveMin for the refresh token.
	 */
	@XmlAttribute(name = "refreshTokenTimeToLiveMin")
	private Integer refreshTokenTimeToLiveMin;

	/**
	 * Overrides tokenTimeToLiveMin for the authorization code.
	 */
	@XmlAttribute(name = "authorizationCodeTimeToLiveMin")
	private Integer authorizationCodeTimeToLiveMin;

	/**
	 * allow to invalidate OIDC sessions before token TTL, keep for 1 minute to allow login sequence termination.
	 * <br/>
	 * Default: 1
 	 */
	@XmlAttribute(name = "sessionTimeToLiveMin")
	@Builder.Default
	private Integer sessionTimeToLiveMin = 1;

	/**
	 * Reuse refresh tokens.
	 * <br/>
	 * Default: false
	 */
	@XmlAttribute(name = "reuseRefreshTokens")
	@Builder.Default
	private Boolean reuseRefreshTokens = Boolean.FALSE;

	/**
	 * ID token signature algorithm (many adapters only support RS256)
	 */
	@XmlAttribute(name = "idTokenSignature")
	private String idTokenSignature;

	/**
	 * Controls the OIDC session cookies sameSite flag None, Strict, Dynamic.
	 * Dynamic: Choose None or Strict based on whether the involved URLs are same site or not.
	 * (A value of Lax while valid has no benefits over Strict and is too restrictive for cross-domain use.)
	 * <br/>
	 * Default: Dynamic
 	 */
	@XmlAttribute(name = "sessionCookieSameSite")
	@Builder.Default
	private String sessionCookieSameSite = WebUtil.COOKIE_SAME_SITE_DYNAMIC;

	public Integer getAccessTokenTimeToLiveMin() {
		if (accessTokenTimeToLiveMin != null) {
			return accessTokenTimeToLiveMin;
		}
		return tokenTimeToLiveMin;
	}

	public Integer getIdTokenTimeToLiveMin() {
		if (idTokenTimeToLiveMin != null) {
			return idTokenTimeToLiveMin;
		}
		return tokenTimeToLiveMin;
	}
}
