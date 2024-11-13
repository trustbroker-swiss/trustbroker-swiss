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

package swiss.trustbroker.config.dto;

import java.util.List;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import swiss.trustbroker.common.config.RegexNameValue;

/**
 * OIDC protocol configuration.
 *
 * @see swiss.trustbroker.federation.xmlconfig.OidcClient
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core</a>
 */
@Configuration
@ConfigurationProperties(prefix = "trustbroker.config.oidc")
@Data
public class OidcProperties {

	/**
	 * XTB OIDC issuer ID.
	 */
	private String issuer;

	/**
	 * XTB OIDC perimeter URL.
	 */
	private String perimeterUrl;

	/**
	 * XTB OIDC session termination endpoint.
	 */
	private String endSessionEndpoint;

	/**
	 * XTB OIDC session iframe endpoint.
	 */
	private String sessionIFrameEndpoint;

	/**
	 * Use session cookies - delete cookies on browser close.
	 * <br/>
	 * Default: true
	 */
	private boolean sessionCookie = true;

	/**
	 * OIDC session lifetime in seconds.
	 */
	private int sessionLifetimeSec;

	/**
	 * Mode for Tomcat sessions.
	 * <br/>
	 * Default: IN_DB
	 */
	private TomcatSessionMode sessionMode = TomcatSessionMode.IN_DB;

	/**
	 * OIDC identity provider configuration.
	 */
	private OidcIdentityProvider identityProvider;

	/**
	 * Encrypt internal SAML messages to XTB.
	 */
	private boolean samlEncrypt = false;

	/**
	 * Key rotation schedule. Cron expression.
	 */
	private String keySchedule;

	/**
	 * Expiration of keys in minutes.
	 */
	private long keyExpirationMinutes;

	/**
	 * Deletion of expired (rotated) keys in minutes.
	 */
	private long keyDeletionMinutes;

	/**
	 * Enable revocation endpoint.
	 * <br/>
	 * Default: true
	 */
	private boolean revocationEnabled = true;

	/**
	 * Enable introspection endpoint.
	 * <br/>
	 * Default: true
	 */
	private boolean introspectionEnabled = true;

	/**
	 * Enable user info endpoint.
	 * <br/>
	 * Default: true
	 */
	private boolean userInfoEnabled = true;

	/**
	 * Enable logout endpoint.
	 * <br/>
	 * Default: true
	 */
	private boolean logoutEnabled = true;

	/**
	 * Use opaque refresh token.
	 * <br/>
	 * Default: false (i.e. JWT token)
	 */
	private boolean opaqueRefreshTokenEnabled = false;

	/**
	 * Global default QoA.
	 */
	private String defaultQoa;

	/**
	 * Global default for legacy Policy Enforcement Point (PEP) QOA mapping policy configured via <pre>OidcClient.usePepQoa</pre>.
	 */
	private String defaultUsePepQoaPolicy;

	/**
	 * Use Keycloak issuer ID. Support cors headers without preflight and handle Issuer.
	 * <br/>
	 * Default: true
	 */
	private boolean useKeycloakIssuerId = true;

	/**
	 * NOTE: Transparency mode simulates /realms/X URLs and IDs for all clients on redirects etc. in case client adapters are
	 * picky on cross-checking URLs against token claims (like iss) and metadata (like Issuer).
	 * For now, we assume we do not need it.
	 * <br/>
	 * Default: false
 	 */
	private boolean keycloakTransparencyModeOn = false;

	/**
	 * SAML namespace to OIDC mappings.
	 */
	private List<SamlNamespace> samlNamespacesMappedToOidcFormat;

	/**
	 * SAML error code mappings.
	 * <br/>
	 * If the regex contains a capturing group that matches, use the matching part (converted to snake case)
	 * else the value is used to replace the matching status code.
 	 */
	private List<RegexNameValue> samlErrorCodeRegexMappings;

	/**
	 * Default error code for OIDC.
	 * <br/>
	 * Fallback: access_denied
	 */
	private String defaultErrorCode;

	/**
	 * List of HTTP header names and regex matching the value. If any one matches, the request is considered to originate from
	 * Javascript and a JSON response is sent.
	 *
	 * @since 1.7.0
	 */
	private List<RegexNameValue> jsonErrorPageHeaders;

	/**
	 * Internal fallback to add eID OIDC standard-claims
 	 */
	private boolean addEidStandardClaims = false;

	/**
	 * Globally customize OIDC header (e.g. adding option typ=JWT).
	 */
	private List<String> addTokenHeader;

	/**
	 * Globally customize /token and /userinfo output dropping technical claims (typ=JWT and iss=issuer we keep for now).
	 * Claims to add.
	 */
	private List<String> addTokenClaims;

	/**
	 * Claims to remove for user info.
	 */
	private List<String> removeUserInfoClaims;

	/**
	 * 	If we have the same attribute from both original issuer and IDM, drop the original issuer one.
 	 */
	private String[] dropDuplicatedAttributeFromOriginalIssuer;

	/**
	 * Token in form encoded request body parameter allowed.
	 * <br/>
	 * Default: true
	 */
	private boolean tokenInRequestBodyEnabled = true;
}
