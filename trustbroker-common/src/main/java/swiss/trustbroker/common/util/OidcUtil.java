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
package swiss.trustbroker.common.util;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.jwt.JWTClaimNames;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import swiss.trustbroker.common.saml.util.Base64Util;

@Slf4j
public class OidcUtil {

    public static final String DEFAULT_SCOPE = "openid"; // default scope (by default everything is in this, non-compliant)

    public static final String OIDC_CLIENT_ID = "client_id"; // OidcClientMetadataClaimNames.CLIENT_ID

    public static final String REDIRECT_URI = "redirect_uri"; // GET /authorize, /logout

    public static final String ID_TOKEN_HINT = "id_token_hint"; // GET /logout

    public static final String TOKEN_INTROSPECT = "token"; // GET /introspect

    public static final String ACCESS_INTROSPECT = "access_token"; // POST /userinfo e.g. by ruby adapter

    public static final String LOGOUT_REDIRECT_URI = "post_logout_redirect_uri";

    public static final String OIDC_BEARER = "Bearer";

    public static final String HTTP_BASIC = "Basic";

    public static final String OIDC_BEARER_NULL = "Bearer null";

    public static final String OIDC_AUDIENCE = JWTClaimNames.AUDIENCE; // token claim matching client_id

    public static final String OIDC_AUTHORIZED_PARTY = "azp"; // alternate aud claim, if aud is multi-valued

    public static final String OIDC_SUBJECT = JWTClaimNames.SUBJECT; // subject (userExtId and sub_id are XTB alternates)

    public static final String OIDC_ACR_VALUES = "acr_values"; // requested QoA by client

    public static final String OIDC_ISSUER = JWTClaimNames.ISSUER; // token claim

    public static final String OIDC_STATE_ID = "state"; // client state transfer for clickbait prevention

    public static final String OIDC_ERROR = "error"; // error code according to spec

    public static final String OIDC_PROMPT = "prompt"; // client can force authentication...

    public static final String OIDC_PROMPT_NONE = "none";

    public static final String OIDC_PROMPT_LOGIN = "login"; // ...when setting prompt=login

    public static final String OIDC_PROMPT_ACCOUNT = "select_account";

    public static final String OIDC_SESSION_ID = "sid"; // token claim

    public static final String OIDC_SESSION_STATE = "session_state"; // token claim

    public static final String OIDC_TOKEN_TYPE = "typ"; // token claim (Keycloak specific, spec uses JWT as default)

    public static final String OIDC_SCOPE = "scope"; // scope claim

    public static final String OIDC_CODE = "code"; // PKCE code parameter

    public static final String OIDC_REFRESH_TOKEN = "refresh_token"; // non-PKCE

    public static final String OIDC_HEADER_KEYID = "kid";

    public static final String OIDC_HEADER_TYPE_JWT = "JWT";

    private OidcUtil() {
    }

    // https://openid.net/specs/openid-connect-frontchannel-1_0.html
    public static String appendFrontchannelLogoutQueryString(String url, String issuer, String oidcSessionId) {
        if (oidcSessionId == null || issuer == null) {
            // spec requires both or none:
            log.debug("oidcSessionId={} or issuer={} missing, not appending iss/sid", oidcSessionId, issuer);
            return url;
        }
        var params = new LinkedHashMap<String, String>(); // deterministic order mainly for tests
        params.put(OidcUtil.OIDC_ISSUER, issuer);
        params.put(OidcUtil.OIDC_SESSION_ID, oidcSessionId);
        return WebUtil.appendQueryParameters(url, params);
    }

    public static String getClientIdFromTokenClaims(Map<String, Object> claims) {
        // OIDC core 1.0, id_token spec (we are dealing with the authorization token here through usually, but it's the same)
        var azp = getClaimFromClaims(claims, OIDC_AUTHORIZED_PARTY); // OPTION: client_id
        if (azp == null) {
            // let's hope the client_id is actually the first element if LIST
            // ...as tokens are emitted by usm this is always true.
            azp = getClaimFromClaims(claims, OIDC_AUDIENCE); // REQUIRED: [ client_id, other ]
        }
        return azp;
    }

    public static String getClaimFromClaims(Map<String, Object> claims, String claimName) {
        String ret = null;
        if (claims != null) {
            var obj = claims.get(claimName);
            if (obj instanceof String str) {
                ret = str;
            }
            else if (obj instanceof List<?> list && !list.isEmpty()) {
                ret = list.get(0).toString(); // just try the first one ok (we expect clients to be aligned for /userinfo in RP
            }
        }
        return ret;
    }

    public static String getClientIdFromAuthorizationHeader(String header) {
        return getClaimFromAuthorizationHeader(header, OIDC_AUDIENCE);
    }

    public static String getSessionIdFromAuthorizationHeader(String bearer) {
        return getClaimFromAuthorizationHeader(bearer, OIDC_SESSION_ID);
    }

    private static String getUserFromBasicAuth(String basicAuthB64) {
        var basicAuth = new String(Base64Util.decode(basicAuthB64));
        return basicAuth.split(":")[0];
    }

    private static String getClaimFromAuthorizationHeader(String header, String claimName) {
        if (header == null || header.isEmpty()) {
            return null;
        }
        var toks = header.split(" ");
        if (toks.length < 2) {
            log.debug("Ignoring {}={} to check for {}", HttpHeaders.AUTHORIZATION, header, claimName);
            return null;
        }
        if (toks[0].equalsIgnoreCase(OIDC_BEARER)) {
            return getClaimFromJwtToken(toks[1], claimName);
        }
        if (toks[0].equalsIgnoreCase(HTTP_BASIC) && claimName.equals(OIDC_AUDIENCE)) {
            return getUserFromBasicAuth(toks[1]);
        }
        log.debug("Ignoring unknown {}={} type", HttpHeaders.AUTHORIZATION, header);
        return null;
    }

    public static String getClientIdFromJwtToken(String jwtToken) {
        return getClaimFromJwtToken(jwtToken, OIDC_AUDIENCE);
    }

    public static String getSessionIdFromJwtToken(String jwtToken) {
        return getClaimFromJwtToken(jwtToken, OIDC_SESSION_ID);
    }

    public static String getClaimFromJwtToken(String jwtToken, String claimName) {
        if (jwtToken == null) {
            return jwtToken;
        }
        var toks = jwtToken.split("\\.");
        // JWT token?
        if (toks.length != 3) { // yes
            if ("null".equals(jwtToken) || jwtToken.isEmpty()) { // some browser send that
                log.debug("Client sends empty '{}: {} {}'", HttpHeaders.AUTHORIZATION, OIDC_BEARER, jwtToken);
            }
            else {
                log.debug("Non-JWT token encountered: {}", jwtToken);
            }
            return null;
        }
        try {
            var claims = JsonUtil.parseJsonObject(Base64Util.urlDecode(toks[1]), false);
            var claimValue = getClaimFromClaims(claims, claimName);
            log.debug(" JWT token encountered with {}={}", claimName, claimValue);
            return claimValue;
        }
        catch (Exception ex) {
            log.info("Fishy JWT token encountered: {}", jwtToken, ex);
        }
        return null;
    }

    public static boolean isOidcPromptLogin(HttpServletRequest request) {
        if (request != null) {
            var prompt = request.getParameter(OidcUtil.OIDC_PROMPT);
            return OidcUtil.OIDC_PROMPT_LOGIN.equals(prompt) || OidcUtil.OIDC_PROMPT_ACCOUNT.equals(prompt);
        }
        return false;
    }

    public static boolean isOidcPromptNone(HttpServletRequest request) {
        if (request != null) {
            var prompt = request.getParameter(OidcUtil.OIDC_PROMPT);
            return OidcUtil.OIDC_PROMPT_NONE.equals(prompt);
        }
        return false;
    }

    public static String getRedirectUriFromRequest(HttpServletRequest request) {
        var redirectUri = request.getParameter(OidcUtil.REDIRECT_URI);
        if (redirectUri == null) {
            redirectUri = request.getParameter(OidcUtil.LOGOUT_REDIRECT_URI);
        }
        return StringUtil.clean(redirectUri);
    }

    public static String getRealmFromRequestUrl(String requestUri) {
        if (requestUri == null) {
            return null;
        }
        int startInd = requestUri.lastIndexOf("/realms/");
        if (startInd < 0) {
            return null;
        }
        int endInd = requestUri.lastIndexOf("/protocol/");
        if (endInd < startInd) {
            return null;
        }
        return requestUri.substring(startInd + "/realms/".length(), endInd);
    }

    public static String maskedToken(String token) {
        if (token == null) {
            return token;
        }
        var toks = token.split("\\.");
        if (toks.length != 3) {
            return null;
        }
        return toks[0] + "." + toks[1] + "." + "SIG-MASKED";
    }

}
