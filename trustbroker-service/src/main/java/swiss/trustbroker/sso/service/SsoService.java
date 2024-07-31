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

package swiss.trustbroker.sso.service;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.ToIntFunction;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.codec.HTMLEncoder;
import net.shibboleth.shared.security.impl.RandomIdentifierGenerationStrategy;
import org.apache.commons.lang3.StringUtils;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.NameID;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;
import swiss.trustbroker.api.qoa.dto.QualityOfAuthentication;
import swiss.trustbroker.api.qoa.service.QualityOfAuthenticationService;
import swiss.trustbroker.audit.dto.OidcAuditData;
import swiss.trustbroker.audit.service.AuditService;
import swiss.trustbroker.audit.service.InboundAuditMapper;
import swiss.trustbroker.common.dto.CookieParameters;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.Base64Util;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.saml.util.SamlUtil;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.common.util.UrlAcceptor;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.FingerprintCheck;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.SloProtocol;
import swiss.trustbroker.federation.xmlconfig.SloResponse;
import swiss.trustbroker.federation.xmlconfig.SsoGroup;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.saml.dto.SsoParticipant;
import swiss.trustbroker.saml.dto.SsoParticipants;
import swiss.trustbroker.sessioncache.dto.SsoSessionParticipant;
import swiss.trustbroker.sessioncache.dto.SsoState;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.sessioncache.service.StateCacheService;
import swiss.trustbroker.sso.dto.SloNotification;

@Service
@Slf4j
@AllArgsConstructor
public class SsoService {

	@Data
	@RequiredArgsConstructor(staticName = "of")
	@AllArgsConstructor(staticName = "of")
	public static class SsoCookieNameParams {

		public static final String XTB_COOKIE_PREFIX = "XTB_";

		static final String DEFAULT_SSO_GROUP = "SSOGroup.default";

		public static final SsoCookieNameParams ANY = of("");

		@NonNull
		private final String ssoGroupName;

		private String cpIssuerId;

		private String subjectNameId;

		private boolean isGroupOnly() {
			return cpIssuerId == null || subjectNameId == null;
		}

		public String getFullSsoGroupName() {
			if (ssoGroupName.isEmpty()) {
				return ssoGroupName;
			}
			if (cpIssuerId == null) {
				return ssoGroupName;
			}
			return ssoGroupName + '_' + cpIssuerId;
		}
	}

	@Data
	@RequiredArgsConstructor(staticName = "of")
	public static class StateWithCookies {

		@NonNull
		private final StateData stateData;

		@NonNull
		private final List<Cookie> cookiesToExpire;
	}

	public enum SsoSessionOperation {

		JOIN(true), // join SSO session
		STEPUP(false), // step up of SSO session required before join (e.g. QoA in session too low)
		IGNORE(false); // ignore existing session, as AuthnRequest os session is not suitable for SSO

		private final boolean skipCpAuthentication;

		SsoSessionOperation(boolean skipCpAuthentication) {
			this.skipCpAuthentication = skipCpAuthentication;
		}

		public boolean skipCpAuthentication() {
			return skipCpAuthentication;
		}
	}

	@Data
	@Builder
	public static class SloState {

		private boolean responseSent;

		private String logoutSsoGroup;

		@Builder.Default
		private Set<SsoSessionParticipant> sloNotifications = new HashSet<>();

		@Builder.Default
		private List<Cookie> cookiesToExpire = new ArrayList<>();
	}

	static final String VELOCITY_PARAM_XTB_HTTP_METHOD = "XTBHttpMethod";

	static final String VELOCITY_PARAM_XTB_SLO_NOTIFICATIONS = "XTBSloNotifications";

	static final String VELOCITY_PARAM_XTB_SLO_MAX_WAIT = "XTBSloMaxWaitMillis";

	static final String VELOCITY_PARAM_XTB_SLO_MIN_WAIT = "XTBSloMinWaitMillis";

	static final String VELOCITY_PARAM_XTB_SLO_WAIT_FOR_COUNT = "XTBSloWaitForCount";

	static final String VELOCITY_PARAM_XTB_CONSOLE_DEBUG = "XTBSloConsoleDebug";

	static final String VELOCITY_PARAM_ACTION = "action"; // from OpenSaml

	static final String SSO_DISPLAY_OIDC_MARKER = " (OIDC)";

	private final RelyingPartyDefinitions relyingPartyDefinitions;

	private final RelyingPartySetupService relyingPartySetupService;

	private final AuditService auditService;

	private final QualityOfAuthenticationService qoaService;

	private final StateCacheService stateCacheService;

	private final RandomIdentifierGenerationStrategy randomGenerator;

	private final TrustBrokerProperties trustBrokerProperties;

	private final Clock clock;

	String generateCookieName(SsoCookieNameParams nameParams, boolean groupOnly) {
		try {
			// only have group - check for any matching SSO cookie
			var cookieName = SsoCookieNameParams.XTB_COOKIE_PREFIX + nameParams.getFullSsoGroupName();
			// this is called both when creating and matching cookie names, so proper browser encoding must happen here
			cookieName = encodeCookieName(cookieName);
			if (groupOnly || nameParams.isGroupOnly()) {
				return cookieName;
			}
			var name = nameParams.getSsoGroupName() + '|' + nameParams.getCpIssuerId() + '|' + nameParams.getSubjectNameId();
			log.debug("Raw Cookie name: {}", name);
			var digest = MessageDigest.getInstance("SHA-256");
			var data = digest.digest(name.getBytes(StandardCharsets.UTF_8));
			// 32 * 4 / 3 = 43 bytes as the encoder emits no padding (=)
			// plaintext prefix, so we can identify sso cookies:
			// Base64 URL encoding without padding is safe for cookie names
			return cookieName + '_' + Base64Util.urlEncode(data);
		}
		catch (NoSuchAlgorithmException ex) {
			// does not happen, SHA-256 is required
			throw new TechnicalException("Missing required SHA256 algorithm", ex);
		}
	}

	Cookie generateCookie(SsoCookieNameParams nameParams, String sessionId,	Integer sessionLifeTime, boolean secure,
			String sameSite) {
		var cookieName = generateCookieName(nameParams, false);
		// prevent browser from sending expired cookies
		var params = CookieParameters.builder()
									 .name(cookieName)
									 .value(sessionId)
									 .maxAge(sessionLifeTime)
									 .secure(secure)
									 .httpOnly(true)
									 .sameSite(sameSite)
									 .build();
		return WebUtil.createCookie(params);
	}

	public Cookie generateCookie(StateData stateData) {
		var subjectNameId = stateData.getSubjectNameId();
		var ssoState = stateData.getSsoState();
		var sessionId = stateData.getId();
		var sameSite = calculateCookieSameSiteFlag(ssoState);
		var sessionLifeTime = trustBrokerProperties.isUseSessionCookieForSso() ? null : ssoState.getMaxSessionTimeSecs();
		var params = ssoState.isImplicitSsoGroup() ? getCookieSsoGroupName(ssoState.getSsoGroupName()) :
				SsoCookieNameParams.of(ssoState.getSsoGroupName(), stateData.getCpIssuer(), subjectNameId);
		return generateCookie(
				params,
				sessionId, sessionLifeTime, trustBrokerProperties.isSecureBrowserHeaders(), sameSite);
	}

	String calculateCookieSameSiteFlag(SsoState ssoState) {
		var ssoGroup = relyingPartySetupService.getSsoGroupConfig(ssoState.getSsoGroupName(), true);
		// SSO group name could be the result of getImplicitSsoGroupName, which does not exist.
		String sameSite = ssoGroup.isPresent() ? ssoGroup.get().getSessionCookieSameSite() : null;
		if (WebUtil.isSameSiteDynamic(sameSite)) {
			var perimeterUri = WebUtil.getValidatedUri(trustBrokerProperties.getPerimeterUrl());
			var isCrossSite = ssoState.getSsoParticipants().stream().anyMatch(
					participant -> !WebUtil.isSameSite(
							perimeterUri, WebUtil.getValidatedUri(participant.getAssertionConsumerServiceUrl())));
			sameSite = WebUtil.getSameSite(!isCrossSite);
			log.debug("SSOGroup={} allows cookie sameSite={} calculated from current ssoParticipants={}",
					ssoGroup, sameSite, ssoState.getSsoParticipants());
		}
		else {
			log.debug("SSOGroup={} requires cookie sameSite={}", ssoGroup, sameSite);
		}
		return sameSite;
	}

	Optional<StateData> findValidStateFromCookies(SsoCookieNameParams nameParams, Cookie[] cookies) {
		var stateCookies = findValidStateCookies(nameParams, cookies);
		var validStates = findValidStatesFromStateCookies(stateCookies, true);
		return extractOnlyStateFromMap(validStates);
	}

	public Optional<StateData> findValidStateFromCookies(RelyingParty relyingParty, ClaimsParty claimsParty, Cookie[] cookies) {
		var nameParams = getCookieSsoGroupName(relyingParty, claimsParty);
		return findValidStateFromCookies(nameParams, cookies);
	}

	// using implicit SSO group of RP
	public Optional<StateData> findValidStateFromCookies(RelyingParty relyingParty, Cookie[] cookies) {
		var nameParams = getCookieImplicitSsoGroupName(relyingParty);
		var result = findValidStateFromCookies(nameParams, cookies);
		if (result.isEmpty()) {
			log.debug("No session for implicit SSO group found for rpIssuerId={} - check regular SSO", relyingParty.getId());
			nameParams = getCookieSsoGroupName(relyingParty);
			result = findValidStateFromCookies(nameParams, cookies);
		}
		return result;
	}

	public Optional<StateData> findValidStateFromCookies(RelyingParty relyingParty, ClaimsParty claimsParty,
			String subjectNameId, Cookie[] cookies) {
		var nameParams = getCookieSsoGroupName(relyingParty, claimsParty, subjectNameId);
		return findValidStateFromCookies(nameParams, cookies);
	}

	public Optional<StateWithCookies> findValidStateAndCookiesToExpire(SsoCookieNameParams nameParams, Cookie[] cookies) {
		var stateCookies = findValidStateCookies(nameParams, cookies);
		var validStates = findValidStatesFromStateCookies(stateCookies, true);
		var stateData = extractOnlyStateFromMap(validStates);
		if (stateData.isEmpty()) {
			log.info("No SSO session for ssoGroup={}", nameParams.getFullSsoGroupName());
			return Optional.empty();
		}
		if (!stateData.get().isSsoEstablished()) {
			log.warn("SSO session not established sessionId={}", stateData.get().getId());
			return Optional.empty();
		}
		List<Cookie> clearCookies = new ArrayList<>();
		generateExpiredCookies(clearCookies, stateCookies, stateData.get());
		return Optional.of(StateWithCookies.of(stateData.get(), clearCookies));
	}

	private static Optional<StateData> extractOnlyStateFromMap(Map<String, StateData> validStates) {
		return validStates.isEmpty() ? Optional.empty() : Optional.of(validStates.values().iterator().next());
	}

	private Map<String, StateData> findValidStatesFromStateCookies(List<Cookie> stateCookies, boolean onlyFirstMatch) {
		Map<String, StateData> validStates = new HashMap<>();
		for (var cookie : stateCookies) {
			var stateData = findValidStateForId(cookie.getValue(), this.getClass().getSimpleName());
			if (stateData.isPresent()) {
				validStates.put(stateData.get().getId(), stateData.get());
				if (onlyFirstMatch) {
					break;
				}
			}
		}
		return validStates;
	}

	/**
	 * @param nameParams
	 * @param cookies
	 * @return exact matches are first in the list
	 */
	private List<Cookie> findValidStateCookies(SsoCookieNameParams nameParams, Cookie[] cookies) {
		List<Cookie> matchingCookies = new ArrayList<>();
		if (cookies == null) {
			return matchingCookies;
		}
		var cookieName = generateCookieName(nameParams, false);
		var groupPrefix = nameParams.isGroupOnly() ? cookieName : generateCookieName(nameParams, true);
		for (var cookie : cookies) {
			var name = cookie.getName();
			if (name.equals(cookieName)) {
				log.debug("Matched cookieName={}", name);
				matchingCookies.add(0, cookie);
			}
			else if (name.startsWith(groupPrefix)) {
				if (nameParams.isGroupOnly()) {
					log.debug("Matched cookieName={} groupPrefix={}", name, groupPrefix);
					matchingCookies.add(cookie);
				}
				else {
					log.debug("Ignore prefix match for full name params cookieName={} groupPrefix={}", name, groupPrefix);
				}
			}
			// logging for other cookies would be too verbose
		}
		return matchingCookies;
	}

	private Optional<StateData> findValidStateForId(String sessionIdFromCookie, String actor) {
		if (sessionIdFromCookie.isEmpty()) {
			return Optional.empty();
		}

		var stateData = stateCacheService.findValidState(sessionIdFromCookie, actor);
		if (stateData.isEmpty()) {
			return Optional.empty();
		}
		if (stateData.get().getSpStateData() == null) {
			return Optional.empty();
		}

		return stateData;
	}

	List<StateData> findAllValidStatesFromCookies(Cookie[] cookies) {
		List<StateData> result = new ArrayList<>();
		if (cookies == null) {
			return result;
		}
		for (var cookie : cookies) {
			var name = cookie.getName();
			if (name.startsWith(SsoCookieNameParams.XTB_COOKIE_PREFIX)) {
				findValidStateForId(cookie.getValue(), this.getClass().getSimpleName()).ifPresent(result::add);
			}
		}
		return result;
	}

	public String generateRelayState() {
		return SamlUtil.generateRelayState(randomGenerator.generateIdentifier());
	}

	public boolean allowSso(StateData stateData) {
		if (!Boolean.TRUE.equals(stateData.getSignedAuthnRequest())) {
			log.info("No SSO as AuthnRequest not signed for session {}", stateData.getId());
			return false;
		}
		return true;
	}

	public SsoSessionOperation skipCpAuthentication(ClaimsParty claimsParty, RelyingParty relyingParty,
			StateData stateDataByAuthnReq, StateData ssoStateData) {
		if (!validStateForSso(ssoStateData)) {
			return SsoSessionOperation.IGNORE;
		}
		ensureAuthnReqOrImplicitSsoState(stateDataByAuthnReq);
		var requestedContextClasses = stateDataByAuthnReq.getRpContextClasses();
		var signedAuthnRequest = Boolean.TRUE.equals(stateDataByAuthnReq.getSignedAuthnRequest());
		return validAuthnRequestForSso(claimsParty, relyingParty, ssoStateData, stateDataByAuthnReq, signedAuthnRequest,
				requestedContextClasses);
	}

	private boolean validStateForSso(StateData ssoStateData) {
		if (!ssoStateData.isValid()) {
			log.info("State {} is not valid: lifecycle {}", ssoStateData.getId(), ssoStateData.getLifecycle());
			return false;
		}
		if (!ssoStateData.isSsoEstablished()) {
			log.info("State {} has no established SSO session: lifecycle {}, ssoSessionId={}", ssoStateData.getId(),
					ssoStateData.getLifecycle(), ssoStateData.getSsoState());
			return false;
		}
		// ForceAuthn on SSO state is irrelevant
		var ssoState = ssoStateData.getSsoState();
		var maxCachingTime = ssoState.getMaxCachingTimeSecs();
		if (maxCachingTime == 0) {
			maxCachingTime = trustBrokerProperties.getSsoSessionLifetimeSec();
			log.debug("ssoMaxCachingTimeSecs not set in state {}, using default {}s", ssoStateData.getId(), maxCachingTime);
		}
		var lastAuthTimestamp = ssoStateData.getLifecycle().getLastAuthTimestamp();
		if (lastAuthTimestamp == null) {
			// would be a bug in state handling (or incomplete state in a test case)
			log.error("State {} in lifeCycle {} is missing lastAuthnTimestamp ", ssoStateData.getId(), ssoStateData.getLifecycle());
			return false;
		}
		var maxCachingInstant = lastAuthTimestamp.toInstant().plusSeconds(maxCachingTime);
		if (maxCachingInstant.isBefore(clock.instant())) {
			log.info("ssoSessionId={} was last authenticated on {} re-authentication required after {}", ssoStateData.getId(),
					lastAuthTimestamp, maxCachingInstant);
			return false;
		}
		if (ssoStateData.getDeviceId() == null) {
			log.error("Device ID not set for state {}: lifecycle {}", ssoStateData.getId(), ssoStateData.getLifecycle());
			return false;
		}
		return true;
	}

	private SsoSessionOperation validAuthnRequestForSso(ClaimsParty claimsParty, RelyingParty relyingParty, StateData ssoStateData,
			StateData stateDataByAuthnReq, boolean authnRequestSigned, List<String> requestedContextClasses) {
		if (!authnRequestSigned) {
			log.info("AuthnRequest sessionId={} is not signed - cannot do SSO", stateDataByAuthnReq.getId());
			return SsoSessionOperation.IGNORE;
		}
		// ForceAuthn is satisfied when we have a CP response (device check)
		if (Boolean.TRUE.equals(stateDataByAuthnReq.getForceAuthn()) && (stateDataByAuthnReq.getCpResponse() == null)) {
			log.info("AuthnRequest sessionId={} requires re-authentication with CP - cannot do SSO", stateDataByAuthnReq.getId());
			return SsoSessionOperation.IGNORE;
		}
		var authnRequestId = stateDataByAuthnReq.getSpStateData().getId();
		if (ssoStateData.getCompletedAuthnRequests() != null
				&& ssoStateData.getCompletedAuthnRequests().contains(authnRequestId)) {
			log.error("New AuthnRequestId={} was already used in ssoSessionId={} - potential replay attack: {}",
					authnRequestId, ssoStateData.getId(), ssoStateData.getCompletedAuthnRequests());
			return SsoSessionOperation.IGNORE;
		}
		return qoaLevelSufficient(claimsParty, relyingParty, requestedContextClasses, ssoStateData);
	}

	public boolean ssoStateValidForDeviceInfo(ClaimsParty claimsParty, RelyingParty relyingParty, StateData ssoStateData,
			StateData stateDataByAuthnReq, String deviceId, String cpIssuerId) {
		if (!relyingParty.isSsoEnabled()) {
			log.error("Relying party rpIssuer={} has no SSO", relyingParty.getId());
			return false;
		}
		var rpSsoGroup = relyingParty.getSso().getGroupName();
		if (rpSsoGroup == null) {
			log.error("Relying party rpIssuer={} has no SSO group", relyingParty.getId());
			return false;
		}
		if (ssoStateData.getCpResponse() == null) {
			log.error("SSO user on rpIssuer={} has no CP response for sessionId={}",
					relyingParty.getId(), ssoStateData.getId());
			return false;
		}
		if (ssoStateData.getSsoState() == null || ssoStateData.getSsoState().getSsoParticipants().isEmpty()) {
			log.error("SSO user on rpIssuer={} has no SSO participants for ssoSessionId={}",
					relyingParty.getId(), ssoStateData.getId());
			return false;
		}
		var sessionSsoGroup = ssoStateData.getSsoState().getSsoGroupName();
		if (!rpSsoGroup.equals(sessionSsoGroup)) {
			log.error("SSO user on rpIssuer={} has group mismatch between rpSsoGroup={} and sessionSsoGroup={} for sessionId={}",
					relyingParty.getId(), rpSsoGroup, sessionSsoGroup, ssoStateData.getId());
			return false;
		}
		// LastConversationId on SSO session is from the last authentication - cannot check this
		// matching
		if (cpIssuerId == null ||
				!(cpIssuerId.equals(ssoStateData.getCpResponse().getIssuer()) || cpIssuerId.equals(ssoStateData.getCpIssuer()))) {
			log.info("SSO user on rpIssuer={} has CP mismatch between lastCpIssuerRequested={} / lastCpIssuerReceived={} and "
							+ "cpIssuerId={} on sessionId={}",
					relyingParty.getId(), ssoStateData.getCpIssuer(), ssoStateData.getCpResponse().getIssuer(),
					cpIssuerId, ssoStateData.getId());
			return false;
		}
		if (!validateFingerprint(deviceId, ssoStateData, relyingParty.getSso().getFingerprintCheck())) {
			return false;
		}
		// repeat the checks done before device info (for the single CP/no HRD case and as a defense against attacks)
		var ssoOp = validAuthnRequestForSso(claimsParty, relyingParty, ssoStateData, stateDataByAuthnReq,
				ssoStateData.getSignedAuthnRequest(), ssoStateData.getRpContextClasses());
		if (ssoOp != SsoSessionOperation.JOIN) {
			return false;
		}
		return validStateForSso(ssoStateData);
	}

	boolean validateFingerprint(String incomingDeviceId, StateData stateData, FingerprintCheck fingerprintCheck) {
		if (fingerprintCheck == null) {
			fingerprintCheck = FingerprintCheck.STRICT;
		}
		var result = fingerprintCheck.match(incomingDeviceId, stateData.getDeviceId());
		if (!result) {
			log.error("FingerprintCheck={} mismatch for sessionId={}: incomingDeviceId={} vs. stateDeviceId={} - {}",
					fingerprintCheck, stateData.getId(), incomingDeviceId, stateData.getDeviceId(),
					fingerprintCheck.isAllowMismatch() ? "proceeding anyway" : "denying SSO");
		}
		return result || fingerprintCheck.isAllowMismatch();
	}

	private static String getRelyingPartySsoGroupName(RelyingParty relyingParty) {
		var sso = relyingParty.getSso();
		if (sso == null || !sso.isEnabled() || StringUtils.isEmpty(sso.getGroupName())) {
			return SsoCookieNameParams.DEFAULT_SSO_GROUP;
		}
		return sso.getGroupName();
	}

	static SsoService.SsoCookieNameParams getCookieSsoGroupName(RelyingParty relyingParty, ClaimsParty claimsParty) {
		var groupName = getRelyingPartySsoGroupName(relyingParty);
		var result = SsoService.SsoCookieNameParams.of(groupName, claimsParty.getId(), null);
		log.debug("Cookie SSO group name derived from RP {} and cpIssuerId={} is {}",
				relyingParty.getId(), claimsParty.getId(), result.getFullSsoGroupName());
		return result;
	}

	static SsoService.SsoCookieNameParams getCookieImplicitSsoGroupName(RelyingParty relyingParty) {
		var groupName = getImplicitSsoGroupName(relyingParty);
		var result = getCookieSsoGroupName(groupName);
		log.debug("Cookie implicit SSO group name derived from RP {} is {}", relyingParty.getId(), result.getFullSsoGroupName());
		return result;
	}

	static SsoService.SsoCookieNameParams getCookieSsoGroupName(RelyingParty relyingParty) {
		var groupName = getRelyingPartySsoGroupName(relyingParty);
		var result = getCookieSsoGroupName(groupName);
		log.debug("Cookie SSO group name derived from RP {} is {}", relyingParty.getId(), result.getFullSsoGroupName());
		return result;
	}

	private static SsoCookieNameParams getCookieSsoGroupName(String groupName) {
		return SsoCookieNameParams.of(groupName, null, null);
	}

	static SsoService.SsoCookieNameParams getCookieSsoGroupName(RelyingParty relyingParty, ClaimsParty claimsParty,
			String subjectNameId) {
		var groupName = getRelyingPartySsoGroupName(relyingParty);
		var result = SsoService.SsoCookieNameParams.of(groupName, claimsParty.getId(), subjectNameId);
		log.debug("Cookie SSO group name derived from rpIssuerId={} and cpIssuerId={} is {}",
				relyingParty.getId(), claimsParty.getId(), result.getFullSsoGroupName());
		return result;
	}

	static String encodeCookieName(String name) {
		// adhere to cookie name restrictions
		// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
		// the used names are mainly US ASCII with some special characters, so we can replace other chars and still be unique
		return name.replaceAll("[^a-zA-Z0-9._-]", "_");
	}

	String getQoaLevelFromContextClassesOrAuthLevel(StateData idpStateData) {
		var qoa = findHighestQoaFromContextClasses(getIdpAssertedContextClassesFromState(idpStateData).stream()).orElse(null);
		log.debug("QOA {} extracted from CP response", qoa);
		// fallback to config when CP does not send a context class
		if (qoa == null && idpStateData.getCpResponse() != null) {
			var authLevel = idpStateData.getCpResponse().getAuthLevel();
			if (authLevel != null) {
				qoa = qoaService.extractQoaLevelFromAuthLevel(authLevel);
				log.debug("QOA {} used from CP config", qoa);
			}
		}
		// fallback to minimum QOA
		if (qoa == null || qoa.isUnspecified()) {
			qoa = qoaService.getDefaultLevel();
			log.debug("QOA {} used as minimal fallback", qoa);
		}
 		return qoa.getName();
	}

	private static List<String> getIdpAssertedContextClassesFromState(StateData stateData) {
		var contextClasses = (stateData.getCpResponse() == null) ? null : stateData.getCpResponse().getContextClasses();
		if (contextClasses == null) {
			// avoid returning null
			contextClasses = Collections.emptyList();
		}
		return contextClasses;
	}

	// valid QoA levels are all above unknown allowing SSO so if i.e. CP send Kerberos we treat it as 40
	private Optional<QualityOfAuthentication> findHighestQoaFromContextClasses(Stream<String> contextClasses) {
		return contextClasses
				.map(qoaService::extractQoaLevel)
				.filter(QualityOfAuthentication::isRegular)
				.min(SsoService::sortHighestQoaFirst);
	}

	private static int sortHighestQoaFirst(QualityOfAuthentication qoa1, QualityOfAuthentication qoa2) {
		return qoa2.getLevel() - qoa1.getLevel();
	}

	// Comparable.compareTo semantics
	private int compareQoaLevel(String expectedQoa, String assuredQoa) {
		if (expectedQoa == null) {
			return assuredQoa == null ? 0 : -1;
		}
		if (assuredQoa == null) {
			return 1;
		}
		return qoaService.extractQoaLevel(expectedQoa).getLevel() - qoaService.extractQoaLevel(assuredQoa).getLevel();
	}

	// AuthnRequest side decision
	boolean isQoaLevelSufficient(ClaimsParty claimsParty, RelyingParty relyingParty,
			List<String> requestQoas, Optional<String> knownQoa, String sessionId) {
		var qoaSufficient = true; // assume we can login with SSO per default

		// request based decision (including DEBUG logging for request side)
		if (!isQoaEnoughForSso(relyingParty, requestQoas, knownQoa)) {
			qoaSufficient=  false;
		}
		// no required QoAs => treat as all possible QoAs
		// state based decision (including INFO logging for )
		else if (!requestQoas.isEmpty() && knownQoa.isPresent()) {
			if (requestQoas.contains(knownQoa.get())) {
				qoaSufficient = true;
			}
			else {
				qoaSufficient = !stateQoaSmaller(claimsParty, knownQoa.get(), requestQoas, sessionId);
			}
		}

		if (log.isInfoEnabled()) {
			log.info("Perform {} for rpIssuer={} with ssoMinQoa={} based on cpKnownQoa={} requestQoas={}",
					(qoaSufficient ? "local SSO" : "CP login"),
					relyingParty.getId(), getSsoMinQoaLevel(relyingParty),
					knownQoa, requestQoas);
		}
		return qoaSufficient;
	}

	// Check on SSO capability can be used both sides:
	// - AuthnRequest: SSO is possible with _all_ QoA levels (including StrongestPossible except if session QoA is already known)
	// - Response: SSO is signaled when CP sends a known QoA that is sufficient for the RP
	boolean isQoaEnoughForSso(RelyingParty relyingParty, List<String> qoas, Optional<String> knownQoa) {
		var ssoPossible = false;
		var ssoMinQoaLevel = getSsoMinQoaLevel(relyingParty);
		var knownQoaLevel = qoaService.extractQoaLevel(knownQoa.orElse(null));
		for (var requestQoa : qoas) {
			var requestQoALevel = qoaService.extractQoaLevel(requestQoa);
			// consider strongest and unknown
			if (!requestQoALevel.isRegular()) {
				ssoPossible |= (requestQoALevel.isStrongestPossible() &&
						(knownQoa.isEmpty() || knownQoaLevel.getLevel() >= ssoMinQoaLevel));
			}
			// consider real QoA
			else {
				ssoPossible |= requestQoALevel.getLevel() >= ssoMinQoaLevel;
			}
		}
		ssoPossible |= qoas.isEmpty(); // no requested QOAs are treated as all of them
		if (!ssoPossible && knownQoaLevel.getLevel() >= ssoMinQoaLevel) {
			ssoPossible = true;
		}
		if (relyingParty.isSsoEnabled()) {
			log.info("Decided ssoPossible={} on ssoSessionQoas={} having cpQoaLevel={} >= ssoMinQoaLevel={}",
					ssoMinQoaLevel, qoas, knownQoaLevel, ssoMinQoaLevel);
		}
		return ssoPossible;
	}

	private int getSsoMinQoaLevel(RelyingParty relyingParty) {
		var globalSsoMinQoaLevel = trustBrokerProperties.getSsoMinQoaLevel();
		return relyingParty != null ? relyingParty.getSsoMinQoaLevel(globalSsoMinQoaLevel) : globalSsoMinQoaLevel;
	}

	private boolean stateQoaSmaller(ClaimsParty claimsParty, String stateQoa, List<String> requestQoas,
			String sessionId) {
		var stateQoaLevel = qoaService.extractQoaLevel(stateQoa);
		for (String requestQoa : requestQoas) {
			var requestQoALevel = qoaService.extractQoaLevel(requestQoa);

			if (requestQoALevel.isStrongestPossible()) {
				var cpAuthLevel = claimsParty.getStrongestPossibleAuthLevelWithFallback();
				if (cpAuthLevel == null) {
					log.error("Requested strongest possible Qoa, but cpIssuerId={} has no AuthLevel defined => no SSO on sessionId={}",
							claimsParty.getId(), sessionId);
					return true;
				}
				requestQoALevel = qoaService.extractQoaLevelFromAuthLevel(cpAuthLevel);
				log.debug("Requested strongest possible Qoa, cpIssuerId={} AuthLevel={} equals Qoa={} on sessionId={}",
						claimsParty.getId(), cpAuthLevel, requestQoALevel, sessionId);
			}

			if (requestQoALevel.isRegular() && stateQoaLevel.getLevel() >= requestQoALevel.getLevel()) {
				log.info("State Qoa level={} >= request Qoa level={} => SSO on sessionId={}",
						stateQoaLevel, requestQoALevel, sessionId);
				return false;
			}
		}
		log.debug("State Qoa level={} < all request Qoa levels={} => no SSO on sessionId={}",
				stateQoaLevel, requestQoas, sessionId);
		return true;
	}

	private SsoSessionOperation qoaLevelSufficient(ClaimsParty claimsParty, RelyingParty relyingParty,
			List<String> requestedContextClasses, StateData stateData) {
		var authnQoas = extractValidQoasFromContextClasses(requestedContextClasses);

		if (authnQoas.isEmpty()) {
			log.info("No QOA requested in Authn context classes on ssoSessionId={} - can join SSO session", stateData.getId());
			return SsoSessionOperation.JOIN;
		}

		var sessionQoa = Optional.ofNullable(stateData.getSsoState().getSsoQoa());
		if (sessionQoa.isEmpty()) {
			// should not happen as this is checked when the session is established
			var contextClasses = getIdpAssertedContextClassesFromState(stateData);
			if (contextClasses.isEmpty()) {
				log.warn("No QOA stored in ssoSessionId={} - STEPUP required for SSO", stateData.getId());
				return SsoSessionOperation.STEPUP;
			}
			sessionQoa = findHighestQoaInState(contextClasses);
		}

		if (!isQoaLevelSufficient(claimsParty, relyingParty, authnQoas, sessionQoa, stateData.getId())) {
			log.debug("For ssoSessionId={} sessionQoa={} is not sufficient for requestedQoas={} - STEPUP required for SSO",
					stateData.getId(), sessionQoa, authnQoas);
			return SsoSessionOperation.STEPUP;
		}
		log.debug("For ssoSessionId={} sessionQoa={} is sufficient for requestedQoas={} - can join SSO session",
				stateData.getId(), sessionQoa, authnQoas);
		return SsoSessionOperation.JOIN;
	}

	private List<String> extractValidQoasFromContextClasses(List<String> contextClasses) {
		if (contextClasses == null) {
			return Collections.emptyList();
		}
		return contextClasses.stream()
				.filter(authnContextClassRef -> qoaService.extractQoaLevel(authnContextClassRef).isRegular())
				.toList();
	}

	private Optional<String> findHighestQoaInState(List<String> contextClasses) {
		var max = qoaService.getUnspecifiedLevel().getLevel();
		Optional<String> maxlevel = Optional.empty();
		for (String contextClass : contextClasses) {
			var level = qoaService.extractQoaLevel(contextClass).getLevel();
			if (level > max) {
				maxlevel = Optional.of(contextClass);
				max = level;
			}
		}
		return maxlevel;
	}

	public List<Cookie> logoutSsoParticipantById(SsoCookieNameParams ssoCookieNameParams, Cookie[] cookies, String deviceId,
			String participantId) {
		// logging errors here as the state is not as expected in these cases
		List<Cookie> clearCookies = new ArrayList<>();
		if (ssoCookieNameParams.getSsoGroupName().isEmpty()) {
			log.error("No SSO Group Name provided");
			return clearCookies;
		}
		List<Cookie> stateCookies = findValidStateCookies(ssoCookieNameParams, cookies);
		Map<String, StateData> validStates = findValidStatesFromStateCookies(stateCookies, false);
		if (validStates.isEmpty()) {
			log.error("No SSO state found for params {}", ssoCookieNameParams);
			return clearCookies;
		}
		for (var stateDataEntry : validStates.entrySet()) {
			var stateData = stateDataEntry.getValue();
			var rp = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(participantId, null, true);
			var fingerprintCheck = rp != null && rp.isSsoEnabled() ? rp.getSso().getFingerprintCheck() : FingerprintCheck.STRICT;
			if (!validateFingerprint(deviceId, stateData, fingerprintCheck)) {
				throw new RequestDeniedException("Device ID does not match stored fingerprint");
			}
			if (internalLogoutSsoParticipant(stateData, participantId) != null) {
				// send expired cookies back to the browser to clear the cookies for this state:
				generateExpiredCookies(clearCookies, stateCookies, stateData);

				// note: the outbound LogoutRequests would need to be sent via the UI, but it was agreed that this is not done
				// recipients would include the participantId - the logout was not initiated by a logout request
				if (stateData.hasSsoState()) {
					log.debug("Would send Logout requests to {}", stateData.getSsoState().getSsoParticipants());
				}
			}
			else {
				log.error("RP {} did not join session of group {}: {}", participantId, ssoCookieNameParams.getFullSsoGroupName(),
						stateData.getId());
			}
		}
		return clearCookies;
	}

	boolean matchSessionIndices(List<String> sessionIndices, String sessionIndex) {
		if (sessionIndex == null) {
			// should not happen as the SSO session has been established
			log.debug("No session index in session");
			return true;
		}
		// accept if session index is missing or all are empty in request (for SamlMock or clients that do not support the index)
		if (sessionIndices == null) {
			log.debug("No session indices in request");
			return true;
		}
		var allEmpty = true;
		for (var index : sessionIndices) {
			if (sessionIndex.equals(index)) {
				return true;
			}
			allEmpty &= StringUtils.isEmpty(index);
		}
		if (allEmpty) {
			log.debug("All session indexes in request were empty - accepting this");
			return true;
		}
		// could be an error in the LogoutRequest
		log.warn("Session index {} not in list of LogoutRequest {}", sessionIndex, sessionIndices);
		return false;
	}

	static List<SsoSessionParticipant> ssoParticipantsToBeNotifiedOfLogout(Set<SsoSessionParticipant> ssoParticipants,
			String logoutRequestIssuer) {
		return ssoParticipants.stream()
				.filter(part -> !logoutRequestIssuer.equals(part.getRpIssuerId())).toList();
	}

	String internalLogoutSsoParticipant(StateData stateData, String participantId) {
		String result = null;
		if (!stateData.isSsoEstablished()) {
			log.warn("sessionId={} has no SSO established", stateData.getId());
		}
		else {
			var participants = stateData.getSsoState().getSsoParticipants();
			result = matchSessionParticipant(participants, participantId);
			if (result == null) {
				log.warn("rpIssuerId={} is not a participant of ssoSessionId={}: {}", participantId, stateData.getId(),
						participants);
			}
		}
		log.debug("Participant={} triggered invalidation of ssoSessionId={}", participantId, stateData.getId());
		stateCacheService.invalidate(stateData, this.getClass().getSimpleName());
		return result;
	}

	// return RP issuer ID of participant if participantId is in list considering matching rules
	String matchSessionParticipant(Set<SsoSessionParticipant> participants, String participantId) {
		if (StringUtils.isEmpty(participantId)) {
			// should not happen really, issuer is from the LogoutRequest which must have an issuer
			log.warn("No issuer found for SSO session participant matching");
			return null;
		}
		if (participants.stream().anyMatch(participant -> participantId.equals(participant.getRpIssuerId()))) {
			log.debug("Participant={} is in list of session participants: {}", participantId, participants);
			return participantId;
		}
		if (!trustBrokerProperties.isPepIssuerMatchingEnabled(participantId)) {
			return null;
		}
		for (var participant : participants) {
			for (var dropPattern : trustBrokerProperties.getSloIssuerIdDropPatterns()) {
				if (participant.getRpIssuerId() != null &&
						participant.getRpIssuerId().replaceAll(dropPattern, "").equals(participantId)) {
					log.debug("Participant '{}' matches truncated participant: '{}'", participantId, participant);
					return participant.getRpIssuerId();
				}
			}
		}
		return null;
	}

	private void generateExpiredCookies(List<Cookie> clearCookies, List<Cookie> stateCookies, StateData stateData) {
		for (var stateCookie : stateCookies) {
			if (stateCookie.getValue().equals(stateData.getId())) {
				clearCookies.add(generateExpiredCookie(stateCookie));
			}
		}
	}

	private Cookie generateExpiredCookie(Cookie stateCookie) {
		var params = CookieParameters.builder()
									 .name(stateCookie.getName())
									 .value("")
									 .maxAge(0)
									 .secure(trustBrokerProperties.isSecureBrowserHeaders())
									 .httpOnly(true)
									 .build();
		return WebUtil.createCookie(params);
	}

	public Cookie generateExpiredCookie(StateData stateData) {
		return generateExpiredCookie(generateCookie(stateData));
	}

	public SsoParticipants getSsoParticipants(SsoCookieNameParams ssoCookieNameParams, Cookie[] cookies, String deviceId) {
		if (ssoCookieNameParams.getSsoGroupName().isEmpty()) {
			log.debug("No SSO Group Name provided");
			return SsoParticipants.UNDEFINED;
		}
		Optional<StateData> stateData = findValidStateFromCookies(ssoCookieNameParams, cookies);
		if (stateData.isEmpty()) {
			log.debug("No SSO state found");
			return SsoParticipants.UNDEFINED;
		}
		if (!validateFingerprint(deviceId, stateData.get(), FingerprintCheck.STRICT)) {
			log.debug("Fingerprint did not match for state={}", stateData.get().getId());
			return SsoParticipants.UNDEFINED;
		}
		if (!stateData.get().hasSsoState()) {
			log.debug("State {} has no SSO state/participants", stateData.get().getId());
			return SsoParticipants.UNDEFINED;
		}
		return getSessionSsoParticipants(stateData.get());
	}

	public List<SsoParticipants> getAllSsoParticipants(Cookie[] cookies, String deviceId) {
		var states = findAllValidStatesFromCookies(cookies);
		List<SsoParticipants> result = new ArrayList<>();
		for (StateData stateData : states) {
			if (!validateFingerprint(deviceId, stateData, FingerprintCheck.STRICT)) {
				log.debug("Fingerprint did not match for state={}", stateData.getId());
			}
			else if (stateData.hasSsoState()) {
				result.add(getSessionSsoParticipants(stateData));
			}
		}
		return result;
	}

	private SsoParticipants getSessionSsoParticipants(StateData stateData) {
		var ssoState = stateData.getSsoState();
		var lifecycle = stateData.getLifecycle();
		var responseParticipants = ssoState.getSsoParticipants().stream().map(
				participant -> {
					var id = participant.getRpIssuerId();
					if (id == null) {
						id = participant.getOidcClientId() + SSO_DISPLAY_OIDC_MARKER;
					}
					var cp = relyingPartyDefinitions.getClaimsProviderById(participant.getCpIssuerId());
					return new SsoParticipant(id,
							cp.getId(), cp.getButton(), cp.getImg(), cp.getShortcut(), cp.getColor());
				}).collect(Collectors.toSet());
		var result = SsoParticipants.builder()
				.ssoGroupName(ssoState.getSsoGroupName())
				.ssoSubject(stateData.getSubjectNameId())
				.participants(responseParticipants)
				.expirationTime(lifecycle.getExpirationTime())
				.ssoEstablishedTime(lifecycle.getSsoEstablishedTime())
				.build();
		log.debug("SSO participants in session {}: {}", stateData.getId(), result);
		return result;
	}

	public void establishImplicitSso(RelyingParty relyingParty, StateData stateData) {
		if (stateData.isSsoEstablished()) {
			log.debug("Session={} is already SSO, no implicit SSO needed", stateData.getId());
			return;
		}
		var ssoGroup = createImplicitSsoGroup(relyingParty);
		log.info("Implicit ssoGroup={} for rpIssuerId={} and session={}", ssoGroup, relyingParty.getId(), stateData.getId());
		establishSso(relyingParty, stateData, ssoGroup, true);
	}

	private SsoGroup createImplicitSsoGroup(RelyingParty relyingParty) {
		return SsoGroup.builder()
					   .name(getImplicitSsoGroupName(relyingParty))
					   // default session lifetime is long enough for the user to take actions for implicit group,
					   // one timeout is sufficient for this case
					   .maxCachingTimeMinutes(trustBrokerProperties.getSessionLifetimeSec())
					   .maxIdleTimeMinutes(trustBrokerProperties.getSessionLifetimeSec())
					   .maxSessionTimeMinutes(trustBrokerProperties.getSessionLifetimeSec())
					   .build();
	}

	static String getImplicitSsoGroupName(RelyingParty relyingParty) {
		// implicit name is based on unaliased ID as the cookie needs to be matched against that
		var id = relyingParty.getUnaliasedId() != null ? relyingParty.getUnaliasedId() : relyingParty.getId();
		return id.replaceAll("[^A-Za-z0-9.]", ".");
	}

	public void establishSso(RelyingParty relyingParty, StateData stateData, SsoGroup ssoGroup) {
		establishSso(relyingParty, stateData, ssoGroup, false);
	}

	private void establishSso(RelyingParty relyingParty, StateData stateData, SsoGroup ssoGroup, boolean implicitSsoGroup) {
		updateSubjectNameIdInSession(stateData);
		if (!updateQoaInSession(relyingParty, stateData) && !implicitSsoGroup) {
			if (stateData.isSsoEstablished()) {
				log.info("Letting rpIssuerId={} join the ssoSessionId={} despite too low QOA",
						relyingParty.getId(), stateData.getId());
			}
			else {
				log.info("Not establishing SSO with rpIssuerId={} for session={} due to too low QOA",
						relyingParty.getId(), stateData.getId());
				return;
			}
		}
		setSsoGroupInSession(ssoGroup, stateData, implicitSsoGroup);
		var rpIssuerId = stateData.getRpIssuer();
		var acsUrl = stateData.getSpStateData().getAssertionConsumerServiceUrl();
		var cpIssuerId = stateData.getCpResponse().getIssuer();
		var participant = SsoSessionParticipant.builder()
											   .rpIssuerId(rpIssuerId)
											   .cpIssuerId(cpIssuerId)
											   .assertionConsumerServiceUrl(acsUrl)
											   .build();
		stateData.addSsoParticipant(participant);
		log.debug("Added initial participant to SSO session={}: participant={}", stateData.getId(), participant);
		stateCacheService.ssoEstablished(stateData, this.getClass().getSimpleName());

		var ssoSessionId = stateData.getSsoSessionId();
		var oidcSessionId = stateData.getOidcSessionId();
		log.info("SSO established for cpIssuer={} cpSessionId={} ssoSessionId={} on rpParticipant={} rpSession={} oidcSession={}",
				cpIssuerId, stateData.getId(), ssoSessionId, rpIssuerId, stateData.getSpStateData().getId(), oidcSessionId);
	}

	static void updateSubjectNameIdInSession(StateData ssoStateData) {
		var nameIdFromIdp = checkAndExtractNameId(ssoStateData);

		log.debug("Set subject idpNameId={} from IDP response for ssoSessionId={} / subjectNameId={}", nameIdFromIdp,
				ssoStateData.getId(), ssoStateData.getSubjectNameId());
		ssoStateData.setSubjectNameId(nameIdFromIdp);
	}

	private static String checkAndExtractNameId(StateData ssoStateData) {
		if (ssoStateData.getCpResponse() == null) {
			// this would be a bug
			throw new TechnicalException(
					String.format("Cannot set subjectNameId in ssoSessionId=%s due to missing IDP response",ssoStateData.getId()));
		}
		var originalNameId = ssoStateData.getCpResponse().getOriginalNameId();
		if (ssoStateData.getSubjectNameId() != null && !ssoStateData.getSubjectNameId().equals(originalNameId)) {
			// this would be a bug, the match needs to be checked before
			throw new TechnicalException(String.format(
							"Cannot change in ssoSessionId=%s from subjectNameId=%s to originalNameId=%s",
							ssoStateData.getId(), ssoStateData.getSubjectNameId(), originalNameId));
		}
		return originalNameId;
	}

	public static boolean isOidcPrincipalAllowedToJoinSsoSession(StateData ssoStateData, String userPrincipal,
			String oidcSessionId) {
		if (!ssoStateData.isSsoEstablished()) {
			log.debug("Skip non-SSO join of participant oidcSessionId={} userPrincipal=\"{}\" to "
							+ "ssoSessionId={} subjectNameId={}",
					oidcSessionId, userPrincipal, ssoStateData.getId(), ssoStateData.getSubjectNameId());
			return false;
		}
		// throws exception on subject change (would be a bug if this happens on OIDC side)
		var subjectNameId = checkAndExtractNameId(ssoStateData);
		log.debug("SSO join of OIDC participant oidcSessionId={} userPrincipal=\"{}\" to ssoSessionId={} subjectNameId={}",
					oidcSessionId, userPrincipal, ssoStateData.getId(), subjectNameId);
		return true;
	}

	public void completeDeviceInfoPreservingStateForSso(StateData ssoStateData, StateData stateDataByAuthnReq,
			RelyingParty relyingParty) {
		ensureSsoState(ssoStateData);
		ensureAuthnReqOrImplicitSsoState(stateDataByAuthnReq);
		copyToSsoStateAndInvalidateAuthnRequestState(stateDataByAuthnReq, ssoStateData);
		var rpIssuerId = relyingParty.getId();
		var ssoGroupName = getRelyingPartySsoGroupName(relyingParty);
		var authReqId = stateDataByAuthnReq.getSpStateData().getId();
		var acsUrl = stateDataByAuthnReq.getSpStateData().getAssertionConsumerServiceUrl();
		ssoStateData.addCompletedAuthnRequest(authReqId);
		addSsoParticipantToSession(ssoGroupName, ssoStateData, rpIssuerId, acsUrl);
		stateCacheService.save(ssoStateData, this.getClass().getSimpleName());
		log.info("Device info completed for session {} / authnRequest {} / issuer {}", ssoStateData.getId(), authReqId, rpIssuerId);
	}

	boolean updateQoaInSession(RelyingParty relyingParty, StateData ssoStateData) {
		var ssoState = ssoStateData.initializedSsoState();
		var cpQoa = getQoaLevelFromContextClassesOrAuthLevel(ssoStateData);
		int diff = compareQoaLevel(cpQoa, ssoState.getSsoQoa());
		if (!isQoaEnoughForSso(relyingParty, List.of(cpQoa), Optional.ofNullable(ssoState.getSsoQoa()))) {
			log.info("Perform session SSO for rpIssuer={} with ssoMinQoa={} based on sessionQoa={} ignoring cpKnownQoa={} diff={}",
					relyingParty.getId(), getSsoMinQoaLevel(relyingParty), ssoState.getSsoQoa(), cpQoa, diff);
			return false;
		}
		log.info("Perform CP SSO for rpIssuer={} with ssoMinQoa={} based on sessionQoa={} applying cpKnownQoa={} diff={}",
				relyingParty.getId(), getSsoMinQoaLevel(relyingParty), ssoState.getSsoQoa(), cpQoa, diff);
		ssoState.setSsoQoa(cpQoa);
		return true;
	}

	private void setSsoGroupInSession(SsoGroup ssoGroup, StateData ssoStateData, boolean implicitSsoGroup) {
		var ssoState = ssoStateData.initializedSsoState();
		ssoState.setSsoGroupName(ssoGroup.getName());
		ssoState.setImplicitSsoGroup(implicitSsoGroup);
		ssoState.setMaxIdleTimeSecs(getSsoGroupTimeoutSecs(ssoGroup, SsoGroup::getMaxIdleTimeMinutes));
		ssoState.setMaxSessionTimeSecs(getSsoGroupTimeoutSecs(ssoGroup, SsoGroup::getMaxSessionTimeMinutes));
		ssoState.setMaxCachingTimeSecs(getSsoGroupTimeoutSecs(ssoGroup, SsoGroup::getMaxCachingTimeMinutes));
	}

	static void addSsoParticipantToSession(String ssoGroupName, StateData ssoStateData, String rpIssuerId, String acsUrl) {
		if (!ssoStateData.hasSsoState()) {
			// only to be used for an established SSO session
			throw new TechnicalException(String.format("Session expected to have an SSO state: %s", ssoStateData.getId()));
		}
		var sessionSsoGroupName = ssoStateData.getSsoState().getSsoGroupName();
		if (sessionSsoGroupName != null && !sessionSsoGroupName.equals(ssoGroupName)) {
			throw new RequestDeniedException(String.format("SSO group name mismatch session %s vs. RP %s",
					sessionSsoGroupName, ssoGroupName));
		}
		var cpIssuerId = ssoStateData.getCpResponse().getIssuer();
		var participant = SsoSessionParticipant.builder()
											   .rpIssuerId(rpIssuerId)
											   .cpIssuerId(cpIssuerId)
											   .assertionConsumerServiceUrl(acsUrl)
											   .build();
		ssoStateData.addSsoParticipant(participant);
		log.info("Added participant to SSO session={}: participant={}", ssoStateData.getId(), participant);
	}

	private int getSsoGroupTimeoutSecs(SsoGroup ssoGroup, ToIntFunction<SsoGroup> func) {
		var timeoutSecs = (int) TimeUnit.MINUTES.toSeconds(func.applyAsInt(ssoGroup));
		return (timeoutSecs > 0) ? timeoutSecs : trustBrokerProperties.getSsoSessionLifetimeSec();
	}

	public SsoSessionOperation prepareRedirectForDeviceInfoAfterHrd(
			Cookie[] cookies,
			StateData stateDataByAuthnReq,
			String claimUrn) {
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(
				stateDataByAuthnReq.getRpIssuer(), stateDataByAuthnReq.getRpReferer());
		var claimsParty = relyingPartySetupService.getClaimsProviderSetupByUrn(claimUrn, stateDataByAuthnReq.getReferer());
		var ssoState = findValidStateFromCookies(relyingParty, claimsParty, cookies);
		if (ssoState.isEmpty()) {
			return SsoSessionOperation.IGNORE;
		}
		var ssoStateData = ssoState.get();
		return skipCpAuthentication(claimsParty, relyingParty, stateDataByAuthnReq, ssoStateData);
	}

	void copyToSsoStateAndInvalidateAuthnRequestState(StateData stateDataByAuthnReq, StateData ssoStateData) {
		if (stateDataByAuthnReq.isSsoEstablished() && !stateDataByAuthnReq.getId().equals(ssoStateData.getId())) {
			if (!stateDataByAuthnReq.getSsoState().isImplicitSsoGroup()) {
				// this never happened, but could be a replay attack - never mix two SSO sessions
				throw new RequestDeniedException(
						String.format("State stateId=%s for authnRequestId=%s is SSO state with different ID than SSO stateId=%s",
								stateDataByAuthnReq.getId(), stateDataByAuthnReq.getSpStateData()
																				.getId(), ssoStateData.getId()));
			}
			else {
				log.debug("Accepting ssoSessionId={} for implicit ssoGroupName={} as AuthnRequest state",
						stateDataByAuthnReq.getId(), stateDataByAuthnReq.getSsoState().getSsoGroupName());
			}
		}

		log.debug("Copying current values from AuthnRequest stateId={} to SSO stateId={}", stateDataByAuthnReq.getId(),
				ssoStateData.getId());

		// copy whole SP state, more maintainable than only copying the values set in AssertionConsumerService.saveState
		ssoStateData.setSpStateData(stateDataByAuthnReq.getSpStateData().toBuilder()
				.lifecycle(stateDataByAuthnReq.getSpStateData().getLifecycle().toBuilder().build()) // deep copy due to invalidate
				.build());
		// SpStateData.contextClasses: not modified after creation, shallow copy is OK

		// copy IDP response too as this corresponds to the more recent authentication
		if (stateDataByAuthnReq.getCpResponse() != null) {
			ssoStateData.setCpResponse(stateDataByAuthnReq.getCpResponse().toBuilder().build());
		}

		// update /verify match
		updateSubjectNameIdInSession(ssoStateData);

		// update rpDestination
		if (ssoStateData.getCpResponse() != null && stateDataByAuthnReq.getSpStateData().getAssertionConsumerServiceUrl() != null) {
			ssoStateData.getCpResponse().setRpDestination(stateDataByAuthnReq.getSpStateData().getAssertionConsumerServiceUrl());
		}

		// these fields are set on the base object in AssertionConsumerService.saveState
		ssoStateData.setLastConversationId(stateDataByAuthnReq.getLastConversationId());
		ssoStateData.setForceAuthn(stateDataByAuthnReq.getForceAuthn());
		ssoStateData.setSignedAuthnRequest(stateDataByAuthnReq.getSignedAuthnRequest());

		if (stateDataByAuthnReq.getId().equals(ssoStateData.getId())) {
			// happens if the HRD selection GET request is sent twice, should not happen normally
			log.error("States for authnRequestId={} and SSO have the same ID, skip invalidation: stateId={}",
					stateDataByAuthnReq.getSpStateData().getId(), stateDataByAuthnReq.getId());
			return;
		}

		log.info("SSO stateId={} is valid for cpId={}, invalidating temporary authnRequestId={} stateId={}", ssoStateData.getId(),
				stateDataByAuthnReq.getCpIssuer(), stateDataByAuthnReq.getSpStateData().getId(), stateDataByAuthnReq.getId());
		stateCacheService.invalidate(stateDataByAuthnReq, this.getClass().getSimpleName());
	}

	// SLO

	List<SsoSessionParticipant> logoutSsoParticipantForLogoutRequest(String logoutRequestIssuerId,
			List<String> logoutRequestSessionIndexes, StateData stateData) {
		// we ignore the result of a mismatch or invalid logout - logout always succeeds from the client's perspective
		matchSessionIndices(logoutRequestSessionIndexes, stateData.getSessionIndex());
		var logoutIssuerId = internalLogoutSsoParticipant(stateData, logoutRequestIssuerId);
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(logoutIssuerId, null, true);

		if (logoutNotificationsEnabled(relyingParty)) {
			// note: the outbound LogoutRequests would need to be sent via the UI, but it was agreed that this is not done
			// LogoutRequest initiated by 'issuer', so we would exclude that one
			var otherParticipants =
					ssoParticipantsToBeNotifiedOfLogout(stateData.getSsoState().getSsoParticipants(), logoutRequestIssuerId);
			log.debug("Other SSO session participants are notified for logoutIssuerId={} rpId={}: {}", logoutIssuerId,
					relyingParty.getId(), otherParticipants);
			return otherParticipants;
		}
		else {
			log.debug("Other SSO session participants are not notified for logoutIssuerId={} rpId={}", logoutIssuerId,
					relyingParty != null ? relyingParty.getId() : null);
			return Collections.emptyList();
		}
	}

	static boolean logoutNotificationsEnabled(RelyingParty relyingParty) {
		return relyingParty != null && relyingParty.isSsoEnabled() && relyingParty.getSso().logoutNotificationsEnabled();
	}

	// returns all RPs matching the referrer, followed by the ones matching the issuer (exact match before near matches)
	// as we need to process all SSO sessions matching either of them to terminate all SLO sessions
	public List<RelyingParty> getRelyingPartiesForSamlSlo(String issuer, String referrer) {
		var allRps = relyingPartySetupService.getOrderedRelyingPartiesForSlo(issuer, referrer);
		var ssoRps = new ArrayList<RelyingParty>();
		for (var rp : allRps) {
			if (rp.getSloUrl(SloProtocol.SAML2).isPresent()) {
				ssoRps.add(rp);
			}
			else {
				log.debug("Dropping LogoutRequest session search for rpIssuer={} having no SSO.sloUrl", rp.getId());
			}
		}
		if (ssoRps.isEmpty()) {
			throw new RequestDeniedException(String.format(
					"Unsupported rpIssuer=%s and referrer=%s for SSO LogoutRequest (no SSO.sloUrl found)",
					issuer, referrer));
		}
		return ssoRps;
	}

	/**
	 * Produce logout notifications for RP. The logoutState is updated accordingly.
	 */
	public Optional<StateData> logoutRelyingParty(String logoutIssuer, List<String> sessionIndexes,
			RelyingParty relyingParty, Cookie[] cookies, SloState logoutState) {
		if (relyingParty.isSsoEnabled()) {
			// identify the cookie(s) that address a state
			var cookieParams = SsoService.SsoCookieNameParams.of(relyingParty.getSso().getGroupName());
			var result = findValidStateAndCookiesToExpire(cookieParams, cookies);
			if (result.isPresent()) {
				var stateWithCookies = result.get();
				var stateData = stateWithCookies.getStateData();
				// referrer matches are processed first, hence the SSO group is based on the referrer if we find a match for
				// that if there is another group, ignore it (still only a heuristic)
				var stateSsoGroup = stateData.getSsoState().getSsoGroupName();
				if (logoutState.logoutSsoGroup == null) {
					logoutState.logoutSsoGroup = stateSsoGroup;
				}
				else if (!logoutState.logoutSsoGroup.equals(stateSsoGroup)) {
					log.info(
							"Not logging out ssoSessionId={} for RP {} as SSO group '{}' is not the one we log out from '{}'",
							stateData.getId(), relyingParty.getId(), stateSsoGroup, logoutState.logoutSsoGroup);
					return Optional.of(stateData);
				}

				log.info("Active ssoSessionId={} found during LogoutRequest for rpIssuerId={} in group {}",
						stateData.getId(), relyingParty.getId(), stateSsoGroup);

				// clean session cookies
				logoutState.cookiesToExpire.addAll(stateWithCookies.getCookiesToExpire());
				logoutState.sloNotifications.addAll(
						logoutSsoParticipantForLogoutRequest(logoutIssuer, sessionIndexes, stateData));
			}
			else {
				log.info("No active SSO session found during LogoutRequest for rpIssuerId={}", relyingParty.getId());
			}
		}
		else {
			log.debug("SSO disabled for rpIssuer={}", relyingParty.getId());
		}
		return Optional.empty();
	}

	public String computeSamlSingleLogoutUrl(String requestReferrer, RelyingParty relyingParty) {
		return computeOidcSingleLogoutUrl(null, requestReferrer, relyingParty, SloProtocol.SAML2);
	}

	public String computeOidcSingleLogoutUrl(String oidcRedirectUrl, String requestReferrer, RelyingParty relyingParty) {
		return computeOidcSingleLogoutUrl(oidcRedirectUrl, requestReferrer, relyingParty, SloProtocol.OIDC);
	}

	private String computeOidcSingleLogoutUrl(String oidcRedirectUrl, String requestReferrer, RelyingParty relyingParty,
			SloProtocol protocol) {
		String sloDestinationUrl = oidcRedirectUrl;
		if (sloDestinationUrl == null) {
			// sloUrl config: Use configured value from RelyingParty setup xml
			Optional<String> sloUrl = relyingParty.getSloUrl(protocol);
			if (sloUrl.isPresent()) {
				sloDestinationUrl = sloUrl.get();
			}
			else {
				sloDestinationUrl = trustBrokerProperties.getSloDefaultDestinationPath(); // XTB knows PEPs
			}
		}
		if (requestReferrer != null) {
			if (sloDestinationUrl == null) {
				sloDestinationUrl = requestReferrer; // sloUrl default: Use RP referer
			}
			else if (WebUtil.isValidRelativeUrl(sloDestinationUrl)) {
				// sloUrl fallback: Construct a value from HTTP referer when the referrer does not have a path (PEP speciality)
				sloDestinationUrl = appendPathToReferrer(requestReferrer, sloDestinationUrl);
			}
		}
		log.debug("Computed {} SLO URL for rpIssuer={} from referrer={} resulting in sloUrl={}",
				protocol, relyingParty.getId(), requestReferrer, sloDestinationUrl);
		return sloDestinationUrl;
	}

	private static String appendPathToReferrer(String requestReferrer, String sloDestinationPath) {
		try {
			var uri = URI.create(requestReferrer);
			// single character SloDefaultDestinationPath is assumed to be /
			if (uri.getPath().length() <= 1 && sloDestinationPath.length() > 1) {
				var result = uri.resolve(sloDestinationPath).toString();
				log.debug("sloDestinationPath={} resolved relative to requestReferrer={} to url={}",
						sloDestinationPath, requestReferrer, result);
				return result;
			}
		}
		catch (IllegalArgumentException|NullPointerException e) {
			log.warn("Ignoring fishy referrer URL for SLO URL construction: {}", StringUtil.clean(requestReferrer));
			return null;
		}
		log.debug("Using requestReferrer={} for sloDestinationPath={}", requestReferrer, sloDestinationPath);
		return requestReferrer;
	}

	SloNotification buildSloNotification(RelyingParty relyingParty, SloResponse sloResponse, String calculatedSloUrl,
			NameID nameId, String oidcSessionId) {
		var result = new SloNotification(sloResponse);
		var url = calculatedSloUrl != null ? calculatedSloUrl : sloResponse.getUrl();
		if (sloResponse.getProtocol() == SloProtocol.SAML2) {
			var sloIssuer = getSloIssuerWithFallback(sloResponse.getIssuer());
			var logoutRequest = SamlFactory.createLogoutRequest(sloIssuer, url, nameId);
			if (relyingParty.requireSignedLogoutRequest()) {
				var sloSigner = sloResponse.getSloSigner();
				if (sloSigner == null) {
					log.debug("No signer for SAML LogoutRequest for sloUrl={}, using RP signer", url);
					sloSigner = relyingParty.getRpSigner();
				}
				var signatureParameters = relyingParty.getSignatureParametersBuilder()
						.credential(sloSigner)
						.skinnyAssertionNamespaces(trustBrokerProperties.getSkinnyAssertionNamespaces())
						.build();
				SamlFactory.signSignableObject(logoutRequest, signatureParameters);
				log.debug("Signed SAML LogoutRequest for sloUrl={}", url);
			}
			result.setSamlLogoutRequest(SamlUtil.encode(logoutRequest));
			result.setSamlRelayState(generateRelayState());
		}
		else if (sloResponse.getProtocol() == SloProtocol.OIDC) {
			url = appendFrontchannelLogoutQueryString(url, sloResponse.getIssuer(), oidcSessionId);
			if (sloResponse.isOidcSessionRequired() && (oidcSessionId == null)) {
				log.error("OIDC client for rpIssuerId={} requires sid parameter, but OIDC session ID is missing - sloResponse={}",
						relyingParty.getId(), sloResponse);
			}
		}
		result.setEncodedUrl(HTMLEncoder.encodeForHTMLAttribute(url));
		return result;
	}

	private String appendFrontchannelLogoutQueryString(String url, String rpSloIssuer, String oidcSessionId) {
		rpSloIssuer = getSloIssuerWithFallback(rpSloIssuer);
		return OidcUtil.appendFrontchannelLogoutQueryString(url, rpSloIssuer, oidcSessionId);
	}

	public String getSloIssuerWithFallback(String rpSloIssuer) {
		if (StringUtils.isEmpty(rpSloIssuer)) {
			return trustBrokerProperties.getIssuer();
		}
		return rpSloIssuer;
	}

	Collection<SloNotification> createSloNotifications(RelyingParty relyingParty, String referer,
			Set<SsoSessionParticipant> sessionParticipants, NameID nameId, String oidcSessionId) {
		Map<SloResponse, SloNotification> responseMap = new HashMap<>();
		// add notifications SLO URLs configured for RP (ACS URL considered for session participant)
		var acsUrl = getSsoSessionParticipantAcsUrl(relyingParty, sessionParticipants, referer);
		addSloNotifications(relyingParty, acsUrl, true, nameId, oidcSessionId, responseMap);
		for (var participant : sessionParticipants) {
			RelyingParty sessionParticipant = null;
			if (participant.getOidcClientId() != null) {
				sessionParticipant = relyingPartyDefinitions.getRelyingPartyByOidcClientId(
						participant.getOidcClientId(), null, trustBrokerProperties, true);
			}
			if ((sessionParticipant == null) && (participant.getRpIssuerId() != null)) {
				sessionParticipant = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(participant.getRpIssuerId(),
						referer, true);
			}
			if (sessionParticipant != null) {
				// add notification SLO URLs configured for participating RP
				addSloNotifications(sessionParticipant, participant.getAssertionConsumerServiceUrl(), false,
						nameId, participant.getOidcSessionId(), responseMap);
			}
			else {
				// could only happen if the configs have changed since the participant joined - this must not block the logout
				log.error("Missing RP for ssoSessionParticipant={}", participant);
			}
		}
		// null values are the RESPONSE entries - remove them
		return responseMap.values().stream().filter(Objects::nonNull).toList();
	}

	static String getSsoSessionParticipantAcsUrl(RelyingParty relyingParty,
			Set<SsoSessionParticipant> sessionParticipants, String referer) {
		var acUrls = sessionParticipants.stream()
				.filter(participant -> relyingParty.getId().equals(participant.getRpIssuerId()))
				.map(SsoSessionParticipant::getAssertionConsumerServiceUrl).toList();
		// no match found, fallback to referer
		if (acUrls.isEmpty()) {
			log.debug("SSO session contains no acUrls for rpIssuerId={} - using referer={}",
					acUrls, relyingParty.getId(), referer);
			return referer;
		}
		// normal case: single one is used:
		if (acUrls.size() == 1) {
			var acUrl = acUrls.get(0);
			log.debug("SSO session contains acsUrl={} for rpIssuerId={} referer={}", acUrl, relyingParty.getId(), referer);
			return acUrl;
		}
		// special case: if the RP is participating with multiple acsUrls, chose the first matching the referer
		// or first if none is matching
		var refererUri = WebUtil.getValidatedUri(referer);
		var acsUrlsForReferer = acUrls.stream()
				.filter(sloUrl -> UrlAcceptor.isUrlOkForAccessIgnoringPath(refererUri, WebUtil.getValidatedUri(sloUrl)))
				.toList();
		log.debug("SSO session contains acsUrls={} matching referer={} for rpIssuerId={}",
				acsUrlsForReferer, referer, relyingParty.getId());
		// no match, use first of the acUrls
		if (acsUrlsForReferer.isEmpty()) {
			return acUrls.get(0);
		}
		// use first matching (there should be only one):
		return acsUrlsForReferer.get(0);
	}

	void addSloNotifications(RelyingParty relyingParty, String acsUrl, boolean initiatingRp, NameID nameId,
			String oidcSessionId, Map<SloResponse, SloNotification> responseMap) {
		var sso = relyingParty.getSso();
		if (sso == null) {
			log.error("RelyingParty id={} has no SSO configuration, but is SSO session participant", relyingParty.getId());
		}
		else {
			// sloUrl does not have a protocol - use for SAML only
			if (initiatingRp && oidcSessionId == null) {
				var rpSloUrl = relyingParty.getSso().getSloUrl();
				var calculatedSloUrl = calculateSloUrlForAcsUrl(relyingParty, rpSloUrl, acsUrl, false);
				if (calculatedSloUrl != null) {
					// Sso.sloUrl for RP initiating the SLO gets LogoutResponse already, no notification
					responseMap.put(SloResponse.builder().url(calculatedSloUrl).build(), null);
				}
			}

			for (SloResponse response : sso.getSloResponse()) {
				addSloNotificationsForResponse(
						relyingParty, acsUrl, initiatingRp, nameId, oidcSessionId, responseMap, response);
			}
		}
	}

	private void addSloNotificationsForResponse(RelyingParty relyingParty, String acsUrl, boolean initiatingRp,
			NameID nameId, String oidcSessionId, Map<SloResponse, SloNotification> responseMap, SloResponse response) {
		var protocol = oidcSessionId == null ? SloProtocol.SAML2 : SloProtocol.OIDC;
		if (initiatingRp && response.isResponse(protocol)) {
			// RESPONSE for RP initiating the SLO gets LogoutResponse already, no notification
			responseMap.put(response, null);
		}
		// there will be only a few notifications, iteration in loop does not hurt
		if (response.isNotification(protocol) && responseMap.keySet().stream().noneMatch(response::isSameExceptMode)) {
			var calculatedSloUrl = calculateSloUrlForAcsUrl(relyingParty, response.getUrl(), acsUrl, response.matchAcUrl());
			if (calculatedSloUrl != null) {
				// no identical notification as RESPONSE or other NOTIFY type yet, add
				responseMap.put(response,
						buildSloNotification(relyingParty, response, calculatedSloUrl, nameId, oidcSessionId));
			}
		}
	}

	// errors logged are really configuration / state issues that should not happen - just ignore these to make the logout work
	static String calculateSloUrlForAcsUrl(RelyingParty relyingParty, String sloUrl, String acsUrl, boolean matchAcUrl) {
		if (sloUrl == null) {
			return null;
		}
		var sloUri = WebUtil.getValidatedUri(sloUrl);
		if (sloUri == null) {
			log.error("sloUrl={} is not a valid URI for rpIssuerId={}", sloUrl, relyingParty.getId());
			return null;
		}
		if (sloUri.isAbsolute() && (acsUrl == null || !matchAcUrl)) {
			log.debug("Using valid absolute sloUrl={} for rpIssuerId={}", sloUrl, relyingParty.getId());
			return sloUrl;
		}
		var acsUri = WebUtil.getValidatedUri(acsUrl);
		if (acsUri == null) {
			log.error("acsUrl={} is not a valid URI for rpIssuerId={} with sloUrl={} relative or requiring acsUrl match",
					acsUrl, relyingParty.getId(), sloUrl);
			return null;
		}
		if (sloUri.isAbsolute()) {
			if (UrlAcceptor.isUrlOkForAccessIgnoringPath(acsUri, sloUri)) {
				log.debug("Using absolute sloUrl={} matching scheme/host/post of acsUrl={} for rpIssuerId={}",
						sloUrl, acsUrl, relyingParty.getId());
				return sloUrl;
			}
			log.debug("Skipping absolute sloUrl={} that does not match scheme/host/post of acsUrl={} for rpIssuerId={}",
					sloUrl, acsUrl, relyingParty.getId());
			return null;
		}
		var result = acsUri.resolve(sloUri).toString();
		log.debug("Relative sloUrl={} resolved against acsUrl={} for rpIssuerId={} resultSloUrl={}",
				sloUrl, acsUrl, relyingParty.getId(), result);
		return result;
	}

	public void handleLogoutResponse(LogoutResponse response, String relayState, HttpServletRequest httpRequest) {
		// no signature or binding check as the LogoutResponse has no effect
		var stateDataOpt = stateCacheService.findOptional(relayState, this.getClass().getSimpleName());
		// state may already be gone when we receive a LogoutResponse, in that case just audit the ID received as RelayState
		var stateData = stateDataOpt.isPresent() ? stateDataOpt.get() : StateData.builder().id(relayState).build();
		auditLogoutResponseFromRp(httpRequest, response, stateData);
	}

	private void auditLogoutResponseFromRp(HttpServletRequest httpServletRequest,
			LogoutResponse response, StateData stateData) {
		var auditDto = new InboundAuditMapper(trustBrokerProperties)
				.mapFrom(stateData)
				.mapFrom(httpServletRequest)
				.mapFrom(response)
				.build();
		auditService.logInboundSamlFlow(auditDto);
	}

	public void auditLogoutRequestFromRp(HttpServletRequest httpServletRequest, LogoutRequest logoutRequest,
			StateData stateData, RelyingParty relyingParty, OidcAuditData oidcAuditData) {
		var auditDto = new InboundAuditMapper(trustBrokerProperties)
				.mapFrom(stateData)
				.mapFrom(logoutRequest) // map after StateData, latter may contain an IDP response itself (overrides samlType)
				.mapFrom(httpServletRequest)
				.mapFrom(relyingParty)
				.mapFrom(oidcAuditData)
				.build();
		auditService.logInboundSamlFlow(auditDto);
	}

	void ensureSsoState(StateData ssoStateData) {
		if (ssoStateData == null) {
			throw new TechnicalException("Missing SSO state");
		}
		if (!ssoStateData.hasSsoState()) {
			var spStateId = ssoStateData.getSpStateData() != null ? ssoStateData.getSpStateData().getId() : null;
			throw new TechnicalException(String.format("State id=%s spId=%s is not an established SSO state",
					ssoStateData.getId(), spStateId));
		}
	}

	void ensureAuthnReqOrImplicitSsoState(StateData stateDataByAuthnReq) {
		if (stateDataByAuthnReq == null) {
			throw new TechnicalException("Missing authentication state");
		}
		if (stateDataByAuthnReq.getSpStateData() == null) {
			throw new TechnicalException(String.format("Authentication state id=%s is missing an SP state",
					stateDataByAuthnReq.getId()));
		}
		if (stateDataByAuthnReq.hasSsoState()) {
			if (!stateDataByAuthnReq.getSsoState().isImplicitSsoGroup()) {
				throw new TechnicalException(String.format("Authentication state id=%s spId=%s is an established SSO state",
						stateDataByAuthnReq.getId(), stateDataByAuthnReq.getSpStateData().getId()));
			}
			log.debug("Accepting ssoSessionId={} for implicit ssoGroupName={} as AuthnRequest state",
					stateDataByAuthnReq.getId(), stateDataByAuthnReq.getSsoState().getSsoGroupName());
		}
	}

	/**
	 * @param relyingParty
	 * @param referer optional
	 * @param sloNotifications optional (else use empty set), from SSO session
	 * @param nameId optional, from CpResponse
	 * @param oidcSessionId optional, from OIDC session, null for logout initiated via SAML
	 * @param oidcRedirectUrl optional, null for logout initiated via SAML
	 * @return parameters for rendering SLO velocity template.
	 */
	public Map<String, Object> buildSloVelocityParameters(RelyingParty relyingParty, String referer,
			Set<SsoSessionParticipant> sloNotifications, NameID nameId, String oidcSessionId, String oidcRedirectUrl) {
		Map<String, Object> velocityParams = new HashMap<>();
		var notifications = createSloNotifications(relyingParty, referer, sloNotifications, nameId, oidcSessionId);
		// velocity parameters
		// first wait minWait, then if not yet completed 100ms until all are except notify-try are completed
		var maxWait = notifications.isEmpty() ? -1 : trustBrokerProperties.getSloNotificationTimoutMillis();
		var hasNotifyTry = notifications.stream().anyMatch(slo -> slo.getSlo().getMode().isNotifyTry());
		var notifyFailWait = notifications.isEmpty() ? 0 : 100; // just a short time to allow the browser to submit the requests
		var minWait = hasNotifyTry ? trustBrokerProperties.getSloNotificationMinWaitMillis() : notifyFailWait;
		log.debug("Velocity parameters: maxWait={} minWait={} count={} oidcRedirectUrl={}",
				maxWait, minWait, notifications.size(), oidcRedirectUrl);
		velocityParams.put(VELOCITY_PARAM_XTB_SLO_MAX_WAIT, maxWait);
		velocityParams.put(VELOCITY_PARAM_XTB_SLO_MIN_WAIT, minWait);
		velocityParams.put(VELOCITY_PARAM_XTB_SLO_WAIT_FOR_COUNT, notifications.size());
		velocityParams.put(VELOCITY_PARAM_XTB_SLO_NOTIFICATIONS, notifications);
		velocityParams.put(VELOCITY_PARAM_XTB_CONSOLE_DEBUG, log.isDebugEnabled());
		if (oidcRedirectUrl != null) {
			velocityParams.put(VELOCITY_PARAM_XTB_HTTP_METHOD, HttpMethod.GET.name());
			velocityParams.put(VELOCITY_PARAM_ACTION, oidcRedirectUrl);
		}
		return velocityParams;
	}

}
