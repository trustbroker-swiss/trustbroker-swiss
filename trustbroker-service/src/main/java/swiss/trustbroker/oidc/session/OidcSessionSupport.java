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
package swiss.trustbroker.oidc.session;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.util.CollectionUtils;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;
import swiss.trustbroker.common.dto.CookieParameters;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.NetworkConfig;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.sessioncache.dto.SsoSessionParticipant;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.sessioncache.service.StateCacheService;
import swiss.trustbroker.sso.service.SsoService;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.WebSupport;

@Slf4j
public class OidcSessionSupport {

	// Spring attaches our SAML principal to the HttpSession and SessionRegistry (the correct abstraction) to deal with it
	// is too high up in the software stack, as we also need to replicate HttpSession ro oder service instances/pods.
	static final String SPRING_SECURITY_CONTEXT = HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY;

	// Spring-sec and spring-auth use a (package) private in HttpSessionRequestCache and WebSessionServerRequestCache.
	// So we cannot make this compile-time save, but it's used for exception improvements only anyway.
	static final String SPRING_SECURITY_SAVED_REQUEST = "SPRING_SECURITY_SAVED_REQUEST";

	// Just for debugging puposes we want to know when spring is processing the SAML response on OIDC side
	static final String SAML2_AUTHN_REQUEST = "org.springframework.security.saml2.provider.service.web."
			+ "HttpSessionSaml2AuthenticationRequestRepository.SAML2_AUTHN_REQUEST";

	// Cookie used by tomcat/spring-sec to track HTTP sessions (for single client support ok)
	// See also application.yml declaring this one to switch from JSESSIONID default.
	private static final String CONTAINER_SESSION_COOKIE_NAME = "BSESSION";

	// The OIDC session cookie name is derived from this one and encodes the client_id.
	static final String OIDC_SESSION_COOKIE_NAME_PREFIX = "BSESSION_";

	// The OIDC SSO session cookie name is derived from this one and encodes the client_id.
	static final String OIDC_SSO_SESSION_COOKIE_NAME_PREFIX = "BSSO_";

	// use this to cross-check and validate the session
	static final String OIDC_SESSION_CLIENT_ID = OidcUtil.OIDC_CLIENT_ID;

	// we write our ID in the session to cross-check it for established OIDC clients
	private static final String OIDC_SESSION_SESSION_ID = "OIDC_SESSION_SESSION_ID";

	// remember SSO session ID, so we can find our way back
	private static final String SAML_SSO_SESSION_ID = "SAML_SSO_SESSION_ID";

	// track authenticated subject FYI mainly
	private static final String SPRING_PRINCIPAL_NAME = "SPRING_PRINCIPAL_NAME";

	// forced authentication support flag to prevent loops when pörompt=login comes along
	private static final String OIDC_PROMPT_LOGIN_PENDING = "OIDC_PROMPTLOGIN_PENDING";

	private OidcSessionSupport() {
	}

	public static String getOidcClientId() {
		return getOidcClientId(null, null, null);
	}

	public static String getOidcClientId(HttpServletRequest request) {
		return getOidcClientId(request, null, null);
	}

	// Check HTTP request for all signs of OIDC clients and derive client_id
	// NOTE: Do not refer to session here (otherwise we have a loop finding it)
	public static String getOidcClientId(HttpServletRequest request,
			RelyingPartyDefinitions relyingPartyDefinitions, NetworkConfig networkConfig) {
		if (request == null) {
			request = HttpExchangeSupport.getRunningHttpRequest();
		}
		if (request == null) {
			log.trace("No OIDC session support yet");
			return null;
		}

		// SAML federation exchange between XTB/OIDC and XTB/SAML
		var source = ApiSupport.SPRING_SAML_AUTHENTICATE_CTXPATH;
		var clientId = getSamlExchangeClientId();
		if (clientId == null && !HttpExchangeSupport.isRunningOidcExchange()) {
			// on SAML side we work without spring-security using container sessions
			log.trace("No OIDC exchange triggered on requestUri {}", request.getRequestURI());
			return null;
		}

		// HTTP GET/POST client_id
		if (clientId == null) {
			source = OidcUtil.OIDC_CLIENT_ID;
			clientId = StringUtil.clean(request.getParameter(source));
		}

		// HTTP Authorization Bearer token with aud/azp claim or Basic client_id:secret
		if (clientId == null) {
			source = HttpHeaders.AUTHORIZATION;
			var authHeader = request.getHeader(source);
			clientId = OidcUtil.getClientIdFromAuthorizationHeader(authHeader);
		}

		// HTTP GET /logout id_token_hint
		if (clientId == null) {
			source = OidcUtil.ID_TOKEN_HINT;
			var idTokenHint = StringUtil.clean(request.getParameter(source));
			clientId = OidcUtil.getClientIdFromJwtToken(idTokenHint);
		}

		// HTTP POST /introspect (IETF RFC7662)
		if (clientId == null) {
			source = OidcUtil.TOKEN_INTROSPECT;
			var token = StringUtil.clean(request.getParameter(source));
			clientId = OidcUtil.getClientIdFromJwtToken(token);
		}

		// HTTP POST /userinfo
		if (clientId == null) {
			source = OidcUtil.ACCESS_INTROSPECT;
			var accessToken = StringUtil.clean(request.getParameter(source));
			clientId = OidcUtil.getClientIdFromJwtToken(accessToken);
		}

		// HTTP POST /token
		if (clientId == null) {
			source = OidcUtil.OIDC_REFRESH_TOKEN;
			var refreshToken = StringUtil.clean(request.getParameter(source));
			clientId = OidcUtil.getClientIdFromJwtToken(refreshToken);
		}

		// check our cookie containing the client_id (multiple cookies might match)
		if (clientId == null && relyingPartyDefinitions != null) {
			clientId = getClientIdFromOidcCookie(request, relyingPartyDefinitions, networkConfig);
		}

		// best effort only
		if (clientId == null && relyingPartyDefinitions != null) {
			source = "HTTP";
			clientId = getOidcClientIdFromHttpParams(request, relyingPartyDefinitions, networkConfig);
		}

		if (clientId == null) {
			source = "NONE";
		}
		log.trace("Found OIDC client_id={} from source={} path={} called from {}",
				clientId, source, request.getRequestURI(), WebSupport.getClientHint(request, networkConfig));
		return clientId;
	}

	// Guessing client_id from other HTTP parameters (not according to OIDC spec)
	public static String getOidcClientIdFromHttpParams(HttpServletRequest request,
			RelyingPartyDefinitions relyingPartyDefinitions, NetworkConfig networkConfig) {

		// HTTP GET/POST redirect_uri
		var source = OidcUtil.REDIRECT_URI;
		var url = getRedirectUri(request);
		var realm = OidcUtil.getRealmFromRequestUrl(request.getRequestURI());
		var clientIds = getClientIdsFromMessageUrl(url, realm, relyingPartyDefinitions);

		// HTTP Referer matching to Client config (multiple clients might match)
		if (clientIds.isEmpty()) {
			source = HttpHeaders.REFERER;
			url = request.getHeader(source);
			clientIds = getClientIdsFromMessageUrl(url, realm, relyingPartyDefinitions);
		}

		// HTTP Origin matching to Client config (multiple clients might match)
		if (clientIds.isEmpty()) {
			source = HttpHeaders.ORIGIN;
			url = request.getHeader(source);
			clientIds = getClientIdsFromMessageUrl(url, realm, relyingPartyDefinitions);
		}

		// This is only best-effort matching that can fail for the following reasons:
		// - RedirectUris.ACUrl contain regex that do not match startsWith test
		// - We might find an Oidc Client matching the URL, but it's the wrong one leading to failed client auth or wrong claims
		// Currently happens on trustrbroker-oidcclient logout with just the redirect-uri but no OPTIONAL client_id or
		// id_token_hint. See https://openid.net/specs/openid-connect-rpinitiated-1_0.html fpr details.
		if (clientIds.size() > 1) {
			log.warn("Ambiguous OIDC client configuration from source={} url={} resulting in clientIds='{}' on endpoint={}. "
							+ "Would lead to client auth failures or unexpected claims due to session mismatch. Called from {}",
					source, StringUtil.clean(url), clientIds, request.getRequestURI(),
					WebSupport.getClientHint(request, networkConfig));
			return null; // client request without session context
		}
		else if (!clientIds.isEmpty()) {
			log.info("OIDC client configuration guessed from source={} url={} resulting in clientId={} on endpoint={} {}",
					source, StringUtil.clean(url), clientIds.iterator().next(), request.getRequestURI(),
							WebSupport.getClientHint(request, networkConfig));
		}
		return clientIds.isEmpty() ? null : clientIds.iterator().next();
	}

	// Similar to getOidcClientId we want to locate the containers sub-session referring to the client state
	// This one is essential to attach the HttpSession to the HttpRequest in the TomcatSessionManager.
	public static String getOidcSessionId(HttpServletRequest request,
			RelyingPartyDefinitions relyingPartyDefinitions, NetworkConfig networkConfig) {
		if (request == null) {
			request = HttpExchangeSupport.getRunningHttpRequest();
		}
		if (request == null) {
			log.trace("Cannot locate sid from running HTTP request yet");
			return null;
		}

		// with a known client_id we can switch to a sub-session
		var clientId = getOidcClientId(request, relyingPartyDefinitions, networkConfig);
		if (clientId == null) {
			log.trace("Cannot locate OIDC sub-session without client_id on requestUri={} from {}",
					request.getRequestURI(), WebSupport.getClientHint(request, networkConfig));
			return null;
		}

		// HTTP Authorization Bearer token
		var source = HttpHeaders.AUTHORIZATION;
		var authHeader = request.getHeader(source);
		var oidcSessionId = OidcUtil.getSessionIdFromAuthorizationHeader(authHeader);

		// HTTP GET /logout id_token_hint
		if (oidcSessionId == null) {
			source = OidcUtil.ID_TOKEN_HINT;
			var idTokenHint = StringUtil.clean(request.getParameter(source));
			oidcSessionId = OidcUtil.getSessionIdFromJwtToken(idTokenHint);
		}

		// HTTP POST /introspect token
		if (oidcSessionId == null) {
			source = OidcUtil.TOKEN_INTROSPECT;
			var introspectToken = StringUtil.clean(request.getParameter(source));
			oidcSessionId = OidcUtil.getSessionIdFromJwtToken(introspectToken);
		}

		// HTTP POST /userinfo
		if (oidcSessionId == null) {
			source = OidcUtil.ACCESS_INTROSPECT;
			var accessToken = StringUtil.clean(request.getParameter(source));
			oidcSessionId = OidcUtil.getSessionIdFromJwtToken(accessToken);
		}

		// HTTP POST /token
		if (oidcSessionId == null) {
			source = OidcUtil.OIDC_REFRESH_TOKEN;
			var refreshToken = StringUtil.clean(request.getParameter(source));
			oidcSessionId = OidcUtil.getSessionIdFromJwtToken(refreshToken);
		}

		// HTTP GET/POST Cookie (BSESSION_CLIENT_ID) during federated login and for resilient code flow backing
		if (oidcSessionId == null) {
			source = "COOKIE";
			oidcSessionId = getSessionIdFromOidcCookie(request, clientId, networkConfig);
		}

		// logging only
		if (log.isDebugEnabled()) {
			if (oidcSessionId != null) {
				log.debug("Found OIDC sessionId={} for clientId={} from source={} called on path={} from {}",
						oidcSessionId, clientId, source, request.getRequestURI(),
						WebSupport.getClientHint(request, networkConfig));
			}
			else if (log.isTraceEnabled()) {
				log.trace("Missing OIDC sessionId for clientId={} from all sources on path={} with cookies='{}' from {}",
						clientId, request.getRequestURI(), StringUtil.clean(request.getHeader(HttpHeaders.COOKIE)),
						WebSupport.getClientHint(request, networkConfig));
			}
		}
		return oidcSessionId;
	}

	public static String getOidcCodeTokenValue(HttpServletRequest request) {
		if (request == null) {
			request = HttpExchangeSupport.getRunningHttpRequest();
		}
		if (request == null) {
			log.trace("Cannot locate code token from running HTTP request yet");
			return null;
		}
		return StringUtil.clean(request.getParameter(OidcUtil.OIDC_CODE));
	}

	public static String getOidcRefreshTokenValue(HttpServletRequest request) {
		if (request == null) {
			request = HttpExchangeSupport.getRunningHttpRequest();
		}
		if (request == null) {
			log.trace("Cannot locate refresh_token token from running HTTP request yet");
			return null;
		}
		return StringUtil.clean(request.getParameter(OidcUtil.OIDC_REFRESH_TOKEN));
	}

	public static String getSessionIdFromOidcCookie(HttpServletRequest request, String clientId, NetworkConfig networkConfig) {
		var cookie = getOidcCookie(request, clientId, networkConfig);
		if (cookie != null) {
			return cookie.getValue();
		}
		return null;
	}

	// maybe discard this one, it's ambiguous and not an official spec compliant approach
	public static String getClientIdFromOidcCookie(HttpServletRequest request,
			RelyingPartyDefinitions relyingPartyDefinitions, NetworkConfig networkConfig) {
		var cookie = getOidcCookie(request, null, networkConfig);
		if (cookie != null) {
			var normalizedClientId = getNormalizedClientId(cookie.getName());
			var client = verifyNormalizedClientId(normalizedClientId, relyingPartyDefinitions);
			return client != null ? client.getId() : null;
		}
		return null;
	}

	static Cookie createOidcCookie(String clientId, String name, String cookieValue, boolean cookieHttpOnly, HttpServletRequest request,
			RelyingPartyDefinitions relyingPartyDefinitions, TrustBrokerProperties trustBrokerProperties) {
		var client = relyingPartyDefinitions.getOidcClientConfigById(clientId, trustBrokerProperties);
		var sessionTtl = getSessionTtlFromClientConfig(client, trustBrokerProperties);
		var cookieSecure = trustBrokerProperties.isSecureBrowserHeaders();
		var cookieSameSite = getCookieSameSite(client, request, trustBrokerProperties);
		var params = CookieParameters.builder()
									 .name(name)
									 .value(cookieValue)
									 .maxAge(sessionTtl)
									 .secure(cookieSecure)
									 .httpOnly(cookieHttpOnly)
									 .sameSite(cookieSameSite)
									 .build();
		return WebUtil.createCookie(params);
	}

	public static Cookie createOidcSsoSessionCookie(String clientId, String cookieValue, HttpServletRequest request,
			RelyingPartyDefinitions relyingPartyDefinitions, TrustBrokerProperties trustBrokerProperties) {
		var name = getSsoSessionCookieName(clientId);
		// Needs to be available to client OIDC JS adapters, thus httpOnly false
		return createOidcCookie(clientId, name, cookieValue, false, request, relyingPartyDefinitions, trustBrokerProperties);
	}

	public static Cookie createOidcClientCookie(String clientId, String sessionId, int validSec, boolean secure,
			String sameSite) {
		var name = getClientIdRelatedCookieName(clientId);
		var params = CookieParameters.builder()
									 .name(name)
									 .value(sessionId)
									 .maxAge(validSec)
									 .secure(secure)
									 .httpOnly(true)
									 .sameSite(sameSite)
									 .build();
		return WebUtil.createCookie(params);
	}

	public static Cookie getOidcCookie(HttpServletRequest request, String clientId, NetworkConfig networkConfig) {
		if (request == null) {
			return null;
		}
		var cookies = request.getCookies();
		if (cookies == null || cookies.length == 0) {
			return null;
		}

		// We return client_id bound cookie without a known client_id as last resort only
		var clientCookieName = getClientIdRelatedCookieName(clientId);
		var bCookies = Arrays.stream(cookies).filter(c -> c.getName().equals(clientCookieName)).toList();
		if (bCookies.size() > 1) {
			// may be even info
			// NOTE: OIDC is usually quite resilient (clients retry, we can prevent interaction enabling SSO)
			var cookiesNames = HttpExchangeSupport.getCookiesAsString(request);
			log.error("Found OIDC bsessionCookies='{}' for clientId={} ambiguous so we deny all to caller {}",
					cookiesNames, clientId, WebSupport.getClientHint(request, networkConfig));
			return null;
		}
		else if (!bCookies.isEmpty()) {
			log.trace("Found OIDC sessionId={} from bsessionCookie={} for clientId={} caller {}",
					bCookies.get(0).getValue(), bCookies.get(0).getName(), clientId,
					WebSupport.getClientHint(request, networkConfig));
			return bCookies.get(0);
		}
		return null;
	}

	// Cookie is BSESSION_CLIENT_ID e.g. BSESSION_SOME-ORG if Client id=some-org in configuration
	// We use this (costly indirection) to add additional security measures later here.
	private static String getNormalizedClientId(String clientId) {
		return clientId != null ? clientId.replace(OIDC_SESSION_COOKIE_NAME_PREFIX, "").toUpperCase() : null;
	}

	private static String getClientIdRelatedCookieName(String clientId) {
		return clientId != null ?
				OIDC_SESSION_COOKIE_NAME_PREFIX + getNormalizedClientId(clientId) :
				CONTAINER_SESSION_COOKIE_NAME; // fallback to global session, we will cross-check the sessionid in there
	}

	private static String getSsoSessionCookieName(String clientId) {
		return OidcSessionSupport.OIDC_SSO_SESSION_COOKIE_NAME_PREFIX + clientId;
	}

	private static OidcClient verifyNormalizedClientId(String normalizedClientId,
			RelyingPartyDefinitions relyingPartyDefinitions) {
		var client = relyingPartyDefinitions.getOidcClientByPredicate(
				c -> getNormalizedClientId(c.getId()).equals(normalizedClientId));
		return client.orElse(null);
	}

	// Multiple redirect_uri mentioned in specifications, some implementations might have mixed them up
	// https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
	public static String getRedirectUri(HttpServletRequest request) {
		var redirectUri = StringUtil.clean(request.getParameter(OidcUtil.LOGOUT_REDIRECT_URI)); // optional
		if (redirectUri == null) {
			// wrong but we have clients sending the same parameter as on /authorize
			redirectUri = StringUtil.clean(request.getParameter(OAuth2ParameterNames.REDIRECT_URI));
		}
		return redirectUri;
	}

	// Use redirect parameters and HTTP headers to match a single client
	private static Set<String> getClientIdsFromMessageUrl(String messageUrl, String realm,
			RelyingPartyDefinitions relyingPartyDefinitions) {
		Set<String> ret = new LinkedHashSet<>();
		if (relyingPartyDefinitions != null && messageUrl != null) {
			// Note: We could speed up locating client with using cl.isValidRedirectUri_s_ but ERROR less precise then
			var clients = relyingPartyDefinitions.getOidcClientsByPredicate(
					cl -> cl.isValidRedirectUri(messageUrl) && cl.isSameRealm(realm));
			clients.forEach(c -> ret.add(c.getId()));
		}
		return ret;
	}

	private static String getOidcSessionId() {
		var session = HttpExchangeSupport.getRunningHttpSession();
		if (session != null) {
			checkSessionHijacking(session);
			return session.getId();
		}
		return null;
	}

	private static String getAttributeFromPrincipal(Saml2AuthenticatedPrincipal principal, AttributeName attributeName) {
		var attrs = principal.getAttribute(attributeName.getNamespaceUri());
		if (CollectionUtils.isEmpty(attrs)) {
			attrs = principal.getAttribute(attributeName.getName());
		}
		if (CollectionUtils.isEmpty(attrs)) {
			log.error("SAML/OIDC session was discarded due to expired session for userPrincipal={}", principal.getName());
			return null;
		}
		return String.valueOf(attrs.get(0));
	}

	static String getSsoSessionIdFromPrincipal(Saml2AuthenticatedPrincipal principal) {
		return getAttributeFromPrincipal(principal, CoreAttributeName.SSO_SESSION_ID);
	}

	public static StateData getStateData() {
		// spring wraps our request again so we either need to unwrap, use attributes or use our TX boundary
		var session = HttpExchangeSupport.getRunningHttpSession();
		if (session != null) {
			return session.getStateData();
		}
		return null;
	}

	public static String getSsoSessionId() {
		var session = getStateData();
		if (session != null) {
			return session.getSsoSessionId();
		}
		return null;
	}

	public static List<String> getSessionIdsFromAuthentication(Authentication authentication) {
		List<String> ret = Collections.emptyList();
		var principal = getSamlPrincipalFromAuthentication(authentication, null);
		if (principal != null) {
			// keep only our own added indexes (they might have even been duplicated by spring-calling us twice)
			ret = new ArrayList<>(principal.getSessionIndexes()); // copy-on-write
			while (ret.size() > 2) {
				ret.remove(0);
			}
		}
		return ret;
	}

	// main authentication context is SAML POST created context from XTB SAML side and the principal is therefore a SAML one
	public static Saml2AuthenticatedPrincipal getSamlPrincipalFromAuthentication(Authentication authentication,
			HttpServletRequest request) {
		var requestURI = request != null ? request.getRequestURI() : null;
		var oidcSessionId = getOidcSessionId();
		if (authentication == null) {
			log.info("No authentication found anymore for requestURI={} oidcSessionId={} from clientIP={}",
					requestURI, oidcSessionId, WebSupport.getClientIp(request));
		}
		else if (authentication.getPrincipal() == null) {
			log.error("Principal missing in authentication={} for requestURI={} oidcSessionId={} from clientIP={}",
					authentication.getName(), requestURI, oidcSessionId, WebSupport.getClientIp(request));
		}
		else if (authentication.getPrincipal() instanceof Saml2AuthenticatedPrincipal principal) {
			return principal;
		}
		else {
			log.error("Fishy principal in spring-security authenticatedPrincipal={}",
					authentication.getPrincipal().getClass());
		}
		return null;
	}

	public static void checkSessionHijacking(HttpSession session) {
		if (session != null) {
			var recordedSession = session.getAttribute(OIDC_SESSION_SESSION_ID);
			if (recordedSession != null && !recordedSession.equals(session.getId())) {
				throw new TechnicalException(String.format(
						"Prevented session hijacking on sessionId=%s owned by oidcSessionId=%s",
						session.getId(), recordedSession));
			}
		}
	}

	public static void setCurrentValuesFromExchange(
			TomcatSession session,
			String clientId,
			AuthenticatedPrincipal principal,
			String ssoSessionId,
			RelyingPartyDefinitions relyingPartyDefinitions,
			TrustBrokerProperties trustBrokerProperties) {
		// track self-references on sessions to detect mistakes
		session.setOidcClientId(clientId);
		session.setAttributeInternal(OIDC_SESSION_CLIENT_ID, clientId);
		session.setAttributeInternal(OIDC_SESSION_SESSION_ID, session.getId());

		// just tracking info (who and if SSO)
		if (ssoSessionId != null) {
			session.setAttributeInternal(OidcSessionSupport.SAML_SSO_SESSION_ID, ssoSessionId);
		}

		// In case of prompt=login we mark the current flow as being in-progress
		var request = HttpExchangeSupport.getRunningHttpRequest(); // we have a session, there must be a request
		if (OidcUtil.isOidcPromptLogin(request)) {
			if (log.isDebugEnabled()) {
				log.debug("Ignoring login SKIPPED for clientId={} with {}={} on endpoint={} called from {}",
						clientId, OidcUtil.OIDC_PROMPT, OidcUtil.OIDC_PROMPT_LOGIN,
						request.getRequestURI(), WebSupport.getClientHint(request, trustBrokerProperties.getNetwork()));
			}

			session.setAttributeInternal(OIDC_PROMPT_LOGIN_PENDING, System.currentTimeMillis());
		}

		// login done we have a principal
		if (principal != null) {
			// leave a trace of the subject on HTTP and XTB session (DEBUG only)
			session.setAttributeInternal(OidcSessionSupport.SPRING_PRINCIPAL_NAME, principal.getName());
			session.setPrincipal(new SessionPrincipal(principal.getName()));
			session.getStateData().setSubjectNameId(principal.getName());
		}

		// NOTE: DB sync is triggered by spring-security context set

		// track on client to survive federation redirects and as a fallback to find auth state
		var cookieName = getClientIdRelatedCookieName(clientId);
		var oidcSessionCookie = createOidcCookie(clientId, cookieName, session.getId(), true,
				request, relyingPartyDefinitions, trustBrokerProperties);
		var httpExchange = HttpExchangeSupport.getRunningHttpExchange();
		httpExchange.getResponse().addCookie(oidcSessionCookie);

		// exchange update also with client info
		// Note: Cookies for HTTP session tracking should only be emitted on OIDC side, SAML works without web session
		var req = httpExchange.getRequest();
		var host = req.getHeader(HttpHeaders.HOST);
		if (principal != null) {
			// Note: Spring security sets the authentication context twice so this also gets logged twice (onResponse, final)
			if (!httpExchange.isAuthContextHandled()) {
				log.info("Established OIDC authentication for clientId={} userName={} ssoSessionId={} oidcSessionId={} "
								+ "trackingCookie={} on host={} requestUrl={} cookieValidSec={} cookieSecure={} ",
						clientId, principal.getName(), ssoSessionId, session.getId(),
						oidcSessionCookie.getName(), host, req.getRequestURL(),
						oidcSessionCookie.getMaxAge(), oidcSessionCookie.getSecure());
				httpExchange.setAuthContextHandled(true);
			}
		}
		else {
			log.debug("Refresh OIDC authentication for clientId={} oidcSessionId={} "
							+ "trackingCookie={} on host={} requestUrl={} cookieValidSec={} cookieSecure={}",
					clientId, session.getId(), oidcSessionCookie.getName(), host, req.getRequestURL(),
					oidcSessionCookie.getMaxAge(), oidcSessionCookie.getSecure());
		}
	}

	// Mainly Set-Cookie BSESSION_CLIENT_ID=sessionid to track the federated login and leave some cross-checking data on the
	// session so we can validate when a session is retrieved not matching the caller context.
	// We keep the cookie as a hint to find client_id and session as a last resort to find the OIDC auth state in
	// getOidcSessionId.
	// NOTE: TomcatSession.getSession == HttpSession, they may have differing IDs potentially but not observed yet
	public static void setFinalValuesFromAuthentication(
			TomcatSession session,
			Object context,
			RelyingPartyDefinitions relyingPartyDefinitions,
			TrustBrokerProperties trustBrokerProperties,
			StateCacheService stateCacheService) {
		var securityContext = (SecurityContext) context;
		var saml2AuthenticatedPrincipal =
				OidcSessionSupport.getSamlPrincipalFromAuthentication(securityContext.getAuthentication(), null);
		if (saml2AuthenticatedPrincipal == null) {
			log.error("Unexpected call to setDerivedValuesFromAuthentication having authentication={} without a SAMl principal",
					securityContext.getAuthentication());
			return;
		}

		// leave some traces of the SAML side in the session
		var clientId = saml2AuthenticatedPrincipal.getRelyingPartyRegistrationId();
		var ssoSessionId = OidcSessionSupport.getSsoSessionIdFromPrincipal(saml2AuthenticatedPrincipal);

		// track in session and on client
		setCurrentValuesFromExchange(session, clientId,
				saml2AuthenticatedPrincipal, ssoSessionId,
				relyingPartyDefinitions, trustBrokerProperties);

		// leave some traces on the spring-sec context
		saml2AuthenticatedPrincipal.getSessionIndexes().add(ssoSessionId); // SAML side
		saml2AuthenticatedPrincipal.getSessionIndexes().add(session.getId()); // OIDC side

		// finally OIDC client as a participant on the SAML/SSO side
		// resilient fetch because we could have DB commit delays
		var ssoSession = stateCacheService.findSessionBySsoSessionIdResilient(ssoSessionId);
		ssoSession.ifPresent(state -> joinSsoSessionAsParticipant(stateCacheService, state,
				saml2AuthenticatedPrincipal, session.getId()));
	}

	// Mainly Set-Cookie BSESSION_CLIENT_ID= to clear it.
	public static void clearDerivedValuesFromAuthentication(
			String clientId, String sessionId, String principalName,
			TrustBrokerProperties trustBrokerProperties) {
		var httpExchange = HttpExchangeSupport.getRunningHttpExchange();
		// best effort, logout might not contain any reference to session or client so we do not clear the cookie then
		if (httpExchange != null && clientId != null) {
			boolean cookieSecure = trustBrokerProperties.isSecureBrowserHeaders();
			discardOidcClientCookie(clientId, httpExchange.getResponse(), cookieSecure);
			if (log.isDebugEnabled()) {
				log.debug("Cleared OIDC authentication for principalName={} clientId={} oidcSessionId={} "
								+ "trackingCookie={} on requestUrl={} cookieSecure={}",
						principalName, clientId, sessionId,
						getClientIdRelatedCookieName(clientId), httpExchange.getRequest().getRequestURL(), cookieSecure);
			}
		}
	}

	// Try our best, not the end of the world if that cookie survives, it's mostly a marker only.
	public static void clearDerivedValuesFromAuthentication(
			TomcatSession session, Object context,
			TrustBrokerProperties trustBrokerProperties) {
		if (context == null) {
			return;
		}
		var securityContext = (SecurityContext) context;
		var saml2AuthenticatedPrincipal =
				OidcSessionSupport.getSamlPrincipalFromAuthentication(securityContext.getAuthentication(), null);
		if (saml2AuthenticatedPrincipal != null) {
			var clientId = saml2AuthenticatedPrincipal.getRelyingPartyRegistrationId();
			clearDerivedValuesFromAuthentication(clientId, session.getId(), saml2AuthenticatedPrincipal.getName(),
					trustBrokerProperties);
		}
	}

	// SSOService creates a mapping session for the StateData.ssoSessionId on establishing a SSO session.
	// A joining OIDC participant si added for GLO handling.
	// If there is no XTB SSO session an OIDC client exists on it's own.
	// So summarized we have these session identifiers:
	// - Primary sessionId (SESS1) belongs to XTB_encoded_cp_subject
	// - SP SAML mapping spSessionId (SESS1): UUID belongs to the relying party
	// - SP OIDC mapping spSessionId (SESS2): BSESSIONID from HTTP session manager for OIDC login/logout
	private static void joinSsoSessionAsParticipant(StateCacheService stateCacheService, StateData stateData,
			Saml2AuthenticatedPrincipal principal, String oidcSessionId) {
		if (!SsoService.isOidcPrincipalAllowedToJoinSsoSession(stateData, principal.getName(), oidcSessionId)) {
			return;
		}

		// OIDC session tracking on SSO session
		stateData.setOidcSessionId(oidcSessionId);
		stateData.getSpStateData().setOidcSessionId(oidcSessionId);
		log.trace("Updated ssoSessionId={} with oidcSessionId={}", stateData.getId(), oidcSessionId);

		// Adding OIDC application clients as session participant is a nice to have feature
		var rpId = principal.getRelyingPartyRegistrationId();
		var cpId = getAttributeFromPrincipal(principal, CoreAttributeName.HOME_REALM);
		var participant = SsoSessionParticipant.builder()
											   .oidcClientId(rpId)
											   .cpIssuerId(cpId)
											   .assertionConsumerServiceUrl(stateData.getRpReferer())
											   .oidcSessionId(oidcSessionId)
											   .build();
		stateData.addSsoParticipant(participant);
		log.debug("Added OIDC participant to SSO session={}: participant={}", stateData.getId(), participant);

		// save
		stateCacheService.save(stateData, OidcSessionSupport.class.getSimpleName());
		log.info("Updated sessionId={} with oidcSessionId={} userPrincipal=\"{}\" sessionIndexes={} rpId={} cpId={}",
				stateData.getId(), oidcSessionId, principal.getName(), principal.getSessionIndexes(), rpId, cpId);
	}

	// return from federated login is done on an OIDC session already
	public static String getSamlExchangeClientId() {
		var request = HttpExchangeSupport.getRunningHttpRequest();
		if (request != null) {
			return getSamlExchangeClientId(request.getRequestURI());
		}
		return null;
	}

	// Federation in both directions
	// /login/saml2/sso/client_id => client_id
	// /saml2/authenticate/client_id => client_id
	public static String getSamlExchangeClientId(String acsUrlPath) {
		if (acsUrlPath != null) {
			// SAML AuthnRequest by OIDC side to SAML side
			if (acsUrlPath.startsWith(ApiSupport.SPRING_SAML_AUTHENTICATE_CTXPATH)) {
				return acsUrlPath.split("/")[3];
			}
			// SAML Response from SAML side to OIDC side
			if (acsUrlPath.startsWith(ApiSupport.SPRING_SAML_FEDERATION_CTXPATH)) {
				return acsUrlPath.split("/")[4];
			}
		}
		return null;
	}

	// Federation from CP to RP on SAML response
	// https://domain/login/saml2/sso/client_id => client_id
	public static String getSamlExchangeAcsUrlClientId(String acsUrl) {
		// SAML AuthnRequest AssertionConsumerService URL recieved on SAM side
		if (acsUrl != null && acsUrl.contains(ApiSupport.SPRING_SAML_FEDERATION_CTXPATH)) {
			return acsUrl.replaceAll(".*" + ApiSupport.SPRING_SAML_FEDERATION_CTXPATH, "");
		}
		return null;
	}

	// To be able to have multiple OIDC clients in parallel we need to discard the global container based cookie
	// tracking as soon as the client got what he needed.
	public static void discardOidcGlobalCookie(HttpServletResponse response, boolean secure) {
		var params = CookieParameters.builder()
									 .name(CONTAINER_SESSION_COOKIE_NAME)
									 .value("")
									 .maxAge(0)
									 .secure(secure)
									 .httpOnly(true)
									 .build();
		var discardCookie = WebUtil.createCookie(params);
		response.addCookie(discardCookie);
	}

	public static void discardOidcClientCookie(String clientId, HttpServletResponse response, boolean secure) {
		var params = CookieParameters.builder()
									 .name(getClientIdRelatedCookieName(clientId))
									 .value("")
									 .maxAge(0)
									 .secure(secure)
									 .httpOnly(true)
									 .build();
		var discardCookie = WebUtil.createCookie(params);
		response.addCookie(discardCookie);
		discardOidcGlobalCookie(response, secure);
	}

	// If client wants to force a login we ignore returning a session, SAML side handles the forceAuthn=true afterward.
	// keycloak.js: Set options.prompt="login" in the console for the /authorize call to trigger a re-login.
	// This will loop because the adapter stores the options in the browser storage so a completed login triggers again
	static TomcatSession invalidateSessionOnPromptLogin(TomcatSession session,
			String idpUrl, String clientId, NetworkConfig networkConfig) {
		if (session == null) {
			return session;
		}

		// discard session for a new login
		var request = HttpExchangeSupport.getRunningHttpRequest();
		if (!OidcUtil.isOidcPromptLogin(request)) {
			var referer = WebUtil.getValidOrigin(WebUtil.getOriginOrReferer(request));
			if (referer != null && referer.equals(idpUrl)) {
				// return from SAML IDP - results in a  redirect to the original URL, which must not trigger another IDP login
				if (log.isDebugEnabled()) {
					log.debug("Ignoring login SKIPPED for clientId={} with {}={} on endpoint={} called from {} with referrer={}",
							clientId, OidcUtil.OIDC_PROMPT, OidcUtil.OIDC_PROMPT_LOGIN,
							request.getRequestURI(), WebSupport.getClientHint(request, networkConfig), referer);
				}
				session.setAttributeInternal(OIDC_PROMPT_LOGIN_PENDING, System.currentTimeMillis());
			}
			return session;
		}

		// we have a marker on our session about an established principal so keycloak.js can fetch the token once
		var loginEstablishedStamp = session.getAttribute(OidcSessionSupport.OIDC_PROMPT_LOGIN_PENDING);
		if (loginEstablishedStamp != null) {
			// keycloak.js relies on getting cached state when /authorize => /token is executed after login
			// we could check on the timestamp here to allow multiple fetches within a defined period of time
			if (log.isDebugEnabled()) {
				log.debug("Forcing login SKIPPED for clientId={} with {}={} on endpoint={} called from {}",
						clientId, OidcUtil.OIDC_PROMPT, OidcUtil.OIDC_PROMPT_LOGIN,
						request.getRequestURI(), WebSupport.getClientHint(request, networkConfig));
			}
			session.removeAttribute(OidcSessionSupport.OIDC_PROMPT_LOGIN_PENDING);
			return session;
		}
		if (log.isInfoEnabled()) {
			log.info("Forcing login for clientId={} with {}={} on endpoint={} called from {}",
					clientId, OidcUtil.OIDC_PROMPT, OidcUtil.OIDC_PROMPT_LOGIN,
					request.getRequestURI(), WebSupport.getClientHint(request, networkConfig));
		}
		// get rid of state
		session.invalidate();
		return null;
	}

	public static void invalidateSsoState(HttpServletRequest request, StateCacheService stateCacheService,
			StateData stateData, String actor) {
		if (!HttpExchangeSupport.isRunningLogoutRequest(request)) {
			return; // keep SSO session
		}
		// find SSO session...
		var ssoSessionId = stateData.getSsoSessionId();
		if (ssoSessionId == null) {
			return;
		}
		var ssoStateData = stateCacheService.findBySsoSessionId(ssoSessionId, actor);
		if (ssoStateData.isEmpty()) {
			return;
		}
		// ...and invalidate it without notifications
		ssoStateData.ifPresent(s -> {
			if (s.getSsoState().getSsoParticipants().size() > 2) {
				log.info("SSO/GLO notifications incomplete triggered by sessionId={} clientId={} participants='{}'",
						stateData.getId(), stateData.getOidcClientId(), s.getSsoState().getSsoParticipants());
			}
			// retain a reference for the SLO handling
			HttpExchangeSupport.getRunningHttpExchange().setSsoState(s);
			stateCacheService.tryInvalidate(s, actor);
		});
	}

	static String getCookieSameSite(Optional<OidcClient> client,
			HttpServletRequest request, TrustBrokerProperties trustBrokerProperties) {
		String sameSite = null;
		if (client.isPresent()) {
			sameSite = client.get().getOidcSecurityPolicies().getSessionCookieSameSite();
		}
		if (WebUtil.isSameSiteDynamic(sameSite)) {
			var redirectUri = getRedirectUri(request);
			if (redirectUri != null) {
				sameSite = WebUtil.getCookieSameSite(trustBrokerProperties.getPerimeterUrl(), redirectUri);
			}
			if (sameSite == null) {
				sameSite = trustBrokerProperties.getCookieSameSite();
			}
		}
		else if (client.isPresent()) { // must be present
			log.debug("OidcClient={} requires cookie sameSite={}", client.get().getId(), sameSite);
		}
		return sameSite;
	}

	private static int getSessionTtlFromClientConfig(Optional<OidcClient> client,
			TrustBrokerProperties trustBrokerProperties) {
		if (trustBrokerProperties.getOidc().isSessionCookie()) {
			return WebSupport.COOKIE_MAXAGE_SESSION;
		}
		// persist cookie marked with configured session TTL
		var ttl = trustBrokerProperties.getOidc().getSessionLifetimeSec(); // 1800
		if (client.isPresent()) {
			var policies = client.get().getOidcSecurityPolicies();
			if (policies.getTokenTimeToLiveMin() != null) { // undefined per default
				ttl = 60 * client.get().getOidcSecurityPolicies().getTokenTimeToLiveMin();
			}
			if (policies.getSessionTimeToLiveMin() != null) { // undefined per default
				ttl = 60 * client.get().getOidcSecurityPolicies().getSessionTimeToLiveMin();
			}
		}
		return ttl;
	}

	public static String getStateParam(HttpServletRequest request) {
		return StringUtil.clean(request.getParameter(OidcUtil.OIDC_STATE_ID));
	}

	public static void addOAuth2AuthorizationTracking(StateData stateData,
			String codeToken, String refreshToken, String authorization, int tokenCount) {
		stateData.setOidcSessionId(codeToken); // primary key
		stateData.setOidcRefreshToken(refreshToken); // init on /token, use on /token
		stateData.setOidcTokenData(authorization);
		stateData.setOidcTokenCount(tokenCount);
	}

	public static void removeOAuth2AuthorizationTracking(StateData stateData) {
		// keys
		stateData.setOidcRefreshToken(null);
		// authorization state
		stateData.setOidcTokenData(null);
		stateData.setOidcTokenCount(0);
	}

	public static String getOAuth2Authorization() {
		var session = HttpExchangeSupport.getRunningHttpSession();
		if (session == null) {
			return null;
		}
		var state = session.getStateData();
		if (state == null) {
			return null;
		}
		return state.getOidcTokenData();
	}

	public static String getSessionInitiator() {
		var request = HttpExchangeSupport.getRunningHttpRequest();
		if (request == null) {
			return null;
		}
		var initiator = getRedirectUri(request);
		if (initiator == null) {
			initiator = WebUtil.getOriginOrReferer(request);
		}
		return initiator;
	}

}
