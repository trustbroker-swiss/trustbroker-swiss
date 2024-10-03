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

package swiss.trustbroker.sessioncache.service;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.OptimisticLockException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.ConcurrencyFailureException;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.tracing.TraceSupport;
import swiss.trustbroker.common.util.ProcessUtil;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.SsoSessionIdPolicy;
import swiss.trustbroker.exception.GlobalExceptionHandler;
import swiss.trustbroker.metrics.service.MetricsService;
import swiss.trustbroker.sessioncache.dto.LifecycleState;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.sessioncache.dto.StateEntity;
import swiss.trustbroker.sessioncache.repo.StateCacheRepository;

@Service
@Slf4j
public class StateCacheService {

	private final StateCacheRepository stateCacheRepository;

	private final TrustBrokerProperties trustBrokerProperties;

	private final GlobalExceptionHandler globalExceptionHandler;

	private final Clock clock;

	private final ObjectMapper objectMapper;

	public final MetricsService metricsService;

	public StateCacheService(StateCacheRepository stateCacheRepository,
			TrustBrokerProperties trustBrokerProperties, GlobalExceptionHandler globalExceptionHandler,
			Clock clock, MetricsService metricsService) {
		this.stateCacheRepository = stateCacheRepository;
		this.trustBrokerProperties = trustBrokerProperties;
		this.globalExceptionHandler = globalExceptionHandler;
		this.clock = clock;
		this.metricsService = metricsService;
		this.objectMapper = new ObjectMapper(); // trusted anything
	}

	public void save(StateData stateData, String actor) {
		var now = clock.instant();
		var expiration = now.plusSeconds(trustBrokerProperties.getSessionLifetimeSec());
		save(stateData, now, expiration, actor);
	}

	public void save(StateData stateData, Instant expiration, String actor) {
		var now = clock.instant();
		save(stateData, now, expiration, actor);
	}

	public void save(StateData stateData, Instant now, Instant expiration, String actor) {
		try {
			if (stateData.getLifecycle().getInitTime() == null) {
				stateData.getLifecycle().setInitTime(Timestamp.from(now));
			}
			if (stateData.getSpStateData() != null && stateData.getSpStateData().getLifecycle().getInitTime() == null) {
				stateData.getSpStateData().getLifecycle().setInitTime(Timestamp.from(now));
			}
			if (stateData.isSsoEstablished() && stateData.getLifecycle().getSsoEstablishedTime() == null) {
				stateData.getLifecycle().setSsoEstablishedTime(Timestamp.from(now));
			}

			var stateEntity = new StateEntity();
			var relayOrRefreshState = getRefreshOrRelayState(stateData); // SAML RelayState, OIDC refresh_token
			var oidcCodeOrSession = getOidcCodeOrSessionState(stateData); // SAML RelayState, OIDC refresh_token
			stateEntity.setId(stateData.getId()); // primary key
			stateEntity.setSpSessionId(relayOrRefreshState); // correlate SP primary key as secondary key
			stateEntity.setOidcSessionId(oidcCodeOrSession);
			updateExpirationTimestamp(now, expiration, stateData, stateEntity);

			encodeAndSaveStateData(stateEntity, stateData, actor, "SAVE");
		}
		catch (TechnicalException ex) {
			throw ex;
		}
		catch (Exception ex) {
			throw new TechnicalException(
					String.format("State save failed in call from actor=%s - Details: stateId=%s exceptionMsg=%s",
					actor, stateData.getId(), ex.getMessage()), ex);
		}
	}

	private static String getRefreshOrRelayState(StateData stateData) {
		var ret = stateData.getOidcRefreshToken();
		if (ret == null) {
			ret = stateData.getSpStateData() != null ? stateData.getSpStateData().getId() : null;
		}
		return ret;
	}

	private static String getOidcCodeOrSessionState(StateData stateData) {
		var ret = stateData.getOidcSessionId();
		if (ret == null) {
			ret = stateData.getId();
		}
		return ret;
	}

	private void updateExpirationTimestamp(Instant now, Instant expiration, StateData stateData, StateEntity stateEntity) {
		if (stateData.isSsoEstablished()) {
			var ssoState = stateData.getSsoState();
			// use SSO group configuration copied into state, fallback to config if not set
			var stateValiditySec = ssoState.getMaxIdleTimeSecs();
			if (stateValiditySec == 0) {
				stateValiditySec = trustBrokerProperties.getSsoSessionLifetimeSec();
				log.debug("SsoMaxIdleTimeSecs not set in sessionId={}, using remainingLifetimeSec={}",
						stateData.getId(), stateValiditySec);
			}
			var maxSessionTimeSec = ssoState.getMaxSessionTimeSecs();
			if (maxSessionTimeSec == 0) {
				maxSessionTimeSec = trustBrokerProperties.getSsoSessionLifetimeSec();
			}
			var latestSessionEndTime =
					stateData.getLifecycle().getSsoEstablishedTime().toInstant().plusSeconds(maxSessionTimeSec);
			expiration = now.plusSeconds(stateValiditySec);
			if (expiration.isAfter(latestSessionEndTime)) {
				log.debug("State EXPIRED before idle timout sessionId={} spSessionId={} oidcSessionId={} "
								+ "latestSessionEndTime={} expirationTime={}",
						stateData.getId(), stateEntity.getSpSessionId(), stateEntity.getOidcSessionId(),
						latestSessionEndTime, expiration);
				expiration = latestSessionEndTime;
			}
		}
		var expirationTimestamp = Timestamp.from(expiration);
		stateData.getLifecycle().setExpirationTime(expirationTimestamp);
		stateEntity.setExpirationTimestamp(expirationTimestamp);
	}

	private StateData extractStateData(StateEntity stateEntity, String actor) {
		try {
			if (log.isDebugEnabled()) {
				var expDuration = Duration.between(clock.instant(), stateEntity.getExpirationTimestamp().toInstant());
				if (log.isTraceEnabled()) {
					log.trace("State FETCH actor={} sessionId={} spSessionId={} oidcSessionId={} expiresInSec={}: {}",
							actor, stateEntity.getId(), stateEntity.getSpSessionId(), stateEntity.getOidcSessionId(),
							expDuration.toSeconds(),
							stateEntity.getJsonData());
				}
				else {
					log.debug("State FETCH actor={} sessionId={} spSessionId={} oidcSessionId={} expiresInSec={}",
							actor, stateEntity.getId(), stateEntity.getSpSessionId(), stateEntity.getOidcSessionId(),
							expDuration.toSeconds());
				}
			}
			var ret = objectMapper.readValue(stateEntity.getJsonData(), StateData.class);
			TraceSupport.switchToConversation(ret.getLastConversationId());
			return ret;
		}
		catch (JsonProcessingException ex) {
			throw new TechnicalException(String.format(
					"Unable to convert JSON to stateData in call from actor=%s - Details: stateId=%s exceptionMsg=%s",
					actor, stateEntity.getId(), ex.getMessage()), ex);
		}
	}

	private void encodeAndSaveStateData(StateEntity stateEntity, StateData stateData, String actor, String event) {
		try {
			// propagate secondary keys
			stateEntity.setSsoSessionId(stateData.getSsoSessionId()); // correlate SSO session secondary key (OIDC login)
			stateEntity.setOidcSessionId(stateData.getOidcSessionId()); // correlate SSO session secondary key (OIDC logout)

			// propagate traceparent if not yet done
			if (stateData.getLastConversationId() == null) {
				stateData.setLastConversationId(TraceSupport.getOwnTraceParent());
			}

			// propagate data
			var jsonData = objectMapper.writeValueAsString(stateData);
			stateEntity.setJsonData(jsonData);

			// debug
			if (log.isDebugEnabled()) {
				var expDuration = Duration.between(clock.instant(), stateEntity.getExpirationTimestamp().toInstant());
				var oidcSession = stateEntity.getOidcSessionId();
				if (log.isTraceEnabled()) {
					log.trace("State {} actor={} sessionId={} spSessionId={} oidcSessionId={} expiresInSec={} DATA: {}",
							event, actor, stateEntity.getId(), stateEntity.getSpSessionId(), oidcSession,
							expDuration.toSeconds(), stateEntity.getJsonData());
				}
				else {
					log.debug("State {} actor={} sessionId={} spSessionId={} oidcSessionId={} expiresInSec={}",
							event, actor, stateEntity.getId(), stateEntity.getSpSessionId(), oidcSession,
							expDuration.toSeconds());
				}
			}

			// persist
			stateCacheRepository.save(stateEntity);
		}
		catch (JsonProcessingException ex) {
			throw new TechnicalException(String.format(
					"Unable to convert stateData to JSON in call from actor=%s - Details: stateId=%s exceptionMsg=%s",
					actor, stateData.getId(), ex.getMessage()), ex);
		}
	}

	// Exception if not found so no parameter required to back-track to session actor
	public StateData find(String id, String actor) {
		var stateEntity = findBySessionId(id, actor);
		return extractStateData(stateEntity, actor);
	}

	// Exception if not found so no parameter required to back-track to session actor
	private StateEntity findBySessionId(String id, String actor) {
		if (id == null) {
			throw new RequestDeniedException(String.format("Missing state ID in call from actor=%s", actor));
		}
		var stateEntity = stateCacheRepository.findById(id);
		if (stateEntity.isEmpty()) {
			throw new RequestDeniedException(String.format("State not found. Details: stateId=%s", StringUtil.clean(id)));
		}
		return stateEntity.get();
	}

	public Optional<StateData> findOptional(String id, String actor) {
		if (id == null) {
			log.info("Missing state ID in call from actor={}", actor);
			return Optional.empty();
		}
		return findBySecondaryId(stateCacheRepository.findById(id).stream(), "sessionId", id, actor);
	}

	// spSessionId required for InResponseTo handling
	public Optional<StateData> findBySpId(String id, String actor) {
		if (id == null) {
			log.info("Missing SP session ID in call from actor={}", actor);
			return Optional.empty();
		}
		return findBySecondaryId(stateCacheRepository.findBySpSessionId(id).stream(), "spSessionId", id, actor);
	}

	// oidcSessionId required to track JESSIONID in spring-authorization-server
	public Optional<StateData> findByOidcSessionId(String id, String actor) {
		if (id == null) {
			log.info("Missing OID session ID in call from actor={}", actor);
			return Optional.empty();
		}
		return findBySecondaryId(stateCacheRepository.findByOidcSessionId(id).stream(), "oidcSessionId", id, actor);
	}

	// ssoSessionId required to correlate XTB OIDC with XTB SAML for participants
	public Optional<StateData> findBySsoSessionId(String id, String actor) {
		if (id == null) {
			log.info("Missing SSO session ID in call from actor={}", actor);
			return Optional.empty();
		}
		// findBySecondaryId with an additional check on isNotOidcSession because OIDC side uses SSO state as well
		var stateDataList = stateCacheRepository.findBySsoSessionId(id).stream()
				.map(
						stateEnt -> {
							var stateData = extractStateData(stateEnt, actor);
							logSessionLoss(stateData, id);
							return stateData;
						})
				.filter(Objects::nonNull)
				.filter(StateData::isValid)
				.filter(StateData::isNotOidcSession)
				.toList();
		return checkAndReturnValidState(stateDataList, "ssoSessionId", id, actor);
	}

	public Optional<StateData> findSessionBySsoSessionIdResilient(String ssoSessionId, String actor) {
		var ret = findBySsoSessionId(ssoSessionId, actor);
		// resilience workaround waiting for +/- 1.5 seconds for TX commit (until we have fixed AppController/RelyingPartyService
		if (SsoSessionIdPolicy.isSsoSession(ssoSessionId)) {
			for (var delay = 100; delay < 1000 && ret.isEmpty(); delay *= 2) { // 4 tries, 100ms, 200ms, 400ms, 800ms
				log.error("No ssoSessionId={} found in DB (yet) in call from actor={} - retrying...", ssoSessionId, actor);
				ProcessUtil.sleep(delay);
				ret = findBySsoSessionId(ssoSessionId, actor);
			}
		}
		return ret;
	}

	// leave some trace if session is gone (un)expectatly
	private static void logSessionLoss(StateData stateData, String id) {
		if (stateData == null || !stateData.isValid()) {
			var msg = String.format("State invalidated already. Details: sessionId=%s lifecycle=%s",
					StringUtil.clean(id), stateData == null ? stateData : stateData.getLifecycle());
			if (id != null && id.startsWith(SsoSessionIdPolicy.SSO_PREFIX)) {
				log.info(msg);
			}
			else {
				log.debug(msg);
			}
			log.trace("StateData details: {}", stateData);
		}
	}

	private Optional<StateData> findBySecondaryId(Stream<StateEntity> stream, String keyName, String id, String actor) {
		if (id == null) {
			log.debug("Missing {} in call from actor={}", keyName, actor);
			return Optional.empty();
		}
		var stateDataList = stream
				.map(stateEnt -> {
					var stateData = extractStateData(stateEnt, actor);
					logSessionLoss(stateData, id);
					return stateData;
				})
				.filter(Objects::nonNull)
				.filter(StateData::isValid)
				.toList();
		return checkAndReturnValidState(stateDataList, keyName, id, actor);
	}

	private static Optional<StateData> checkAndReturnValidState(List<StateData> stateDataList,
			String keyName, String id, String actor) {
		if (stateDataList.isEmpty()) {
			// we expect the receiver of the state data to throw exceptions or deal with it in other ways
			log.debug("State MISS actor={} {}={}", actor, keyName, id);
			return Optional.empty();
		}
		if (stateDataList.size() > 1) {
			throw new RequestDeniedException(String.format(
					"State data created multiple times for %s (possible re-posts) in call from actor=%s - "
							+ "Details: stateId=%s repostCount=%d",
					keyName, actor, StringUtil.clean(id), stateDataList.size()));
		}
		return Optional.of(stateDataList.get(0));
	}

	public Optional<StateData> findValidState(String id, String actor) {
		Optional<StateEntity> stateEntity = stateCacheRepository.findById(id);

		if (stateEntity.isEmpty()) {
			log.debug("State MISS actor={} sessionId={}", actor, id);
			return Optional.empty();
		}

		var expirationTime = stateEntity.get().getExpirationTimestamp().toInstant();
		var currentTime = clock.instant();

		var stateData = extractStateData(stateEntity.get(), actor);
		if (currentTime.isAfter(expirationTime)) {
			// current time is equal to log timestamp except in tests with a fixed clock
			log.error("State EXPIRED for actor={} sessionId={} expirationTime={} currentTime={}",
					actor, id, expirationTime, currentTime);
			invalidate(stateData, actor);
			return Optional.empty();
		}

		// XTB session cookies might end up here with a cookie not cleared in the browser
		if (stateData.isExpired()) {
			log.info("State marked EXPIRED for actor={} sessionId={} expiredTime={}",
					actor, id, stateData.getLifecycle().getExpiredTime());
			return Optional.empty();
		}

		return Optional.of(stateData);
	}

	// Exception if not found so no parameter required to back-track to session actor
	public StateData findMandatoryValidState(String id, String actor) {
		return findValidState(id, actor)
				.orElseThrow(() -> new RequestDeniedException(
						String.format("State not valid in call from actor=%s - Details: stateId=%s", actor, id)));
	}

	public void tryInvalidate(StateData stateData, String actor) {
		try {
			invalidate(stateData, false, actor);
		}
		catch (Exception ex) {
			log.warn("Try invalidating sessionId={} failed: {}", stateData.getId(), ex.getMessage(), ex);
		}
	}

	public void invalidate(StateData stateData, String actor) {
		invalidate(stateData, false, actor);
	}

	public void invalidate(StateData stateData, boolean successfulAuthentication, String actor) {
		// always update lifecycle and timestamps (can be used for auditing)
		stateData.getLifecycle().setLifecycleState(LifecycleState.EXPIRED);
		var now = Timestamp.from(clock.instant());
		stateData.getLifecycle().setExpiredTime(now);
		if (successfulAuthentication) {
			// audit logging is using this
			stateData.getLifecycle().setReauthTime(now);
		}
		if (stateData.getSpStateData() != null) {
			stateData.getSpStateData().getLifecycle().setLifecycleState(LifecycleState.EXPIRED);
			stateData.getSpStateData().getLifecycle().setExpiredTime(now);
		}

		// invalidate in cache if present
		var stateEntity = stateCacheRepository.findById(stateData.getId());
		if (stateEntity.isEmpty()) {
			log.info("State NOTFOUND, no need to invalidate. Details: sessionId={}", stateData.getId());
			return;
		}
		encodeAndSaveStateData(stateEntity.get(), stateData, actor, "INVALIDATE");
	}

	public void ssoEstablished(StateData stateData, String actor) {
		if (!stateData.isValid()) {
			throw new RequestDeniedException(
					String.format("State INVALID in call from actor=%s - cannot establish SSO. Details: stateId=%s",
							actor,stateData.getId()));
		}
		var stateEntity = findBySessionId(stateData.getId(), actor);
		stateData.getLifecycle().setLifecycleState(LifecycleState.ESTABLISHED);
		if (stateData.getSpStateData() != null) {
			stateData.getSpStateData().getLifecycle().setLifecycleState(LifecycleState.ESTABLISHED);
		}

		// update SSO established time
		var now = clock.instant();
		var timeNow = Timestamp.from(now);
		if (stateData.getLifecycle().getSsoEstablishedTime() == null) {
			stateData.getLifecycle().setSsoEstablishedTime(timeNow);
			log.debug("SSO state established. Details: sessionId={} timeNow={}", stateData.getId(), timeNow);
		}
		else {
			stateData.getLifecycle().setReauthTime(timeNow);
			log.debug("SSO state updated. Details: sessionId={} timeNow={}", stateData.getId(), timeNow);
		}

		// update to SSO expiration time
		var expiration = now.plusSeconds(trustBrokerProperties.getSsoSessionLifetimeSec());
		updateExpirationTimestamp(now, expiration, stateData, stateEntity);
		encodeAndSaveStateData(stateEntity, stateData, actor, "ESTABLISH");
	}

	@SuppressWarnings("java:S2245") // use of unsecure random just for randomizing run time between PODs
	@Scheduled(cron = "${trustbroker.config.stateCache.reapSchedule}")
	public void reap() {
		try {
			var randomDelaySec = trustBrokerProperties.getStateCache().getReapMaxDelaySec();
			var randomDelayMs = ThreadLocalRandom.current().nextInt(randomDelaySec > 0 ? randomDelaySec * 1000 : 1);
			Thread.sleep(randomDelayMs);

			var start = clock.instant();
			log.info("Start reaping StateCache (delayMs={})...", randomDelayMs);

			long numEntries = stateCacheRepository.count();
			long expired = reapExpiredSessions(start);
			long collected = reapExpiringSessions(start, numEntries);
			metricsService.gauge(MetricsService.SESSION_LABEL + "active", numEntries-expired);

			// result with tuning recommendations when reaper needs to collect too many sessions
			if (log.isErrorEnabled()) {
				var end = clock.instant();
				var diff = Duration.between(start, end).toMillis();
				var msg = String.format(
						"Completed reaping StateCache in dTms=%s totalSessions=%d expiredSessions=%d collectedSessions=%d",
						diff, numEntries, expired, collected);
				if (diff >= trustBrokerProperties.getStateCache().getReapWarnThresholdMs() ) {
					log.warn(msg + " (HINT: Check statistics, tune DB, decrease load, increase reaper schedule)");
				}
				else {
					log.info(msg);
				}
			}
		}
		// these ones should be gone with using batched delete
		catch (OptimisticLockException | ConcurrencyFailureException ex) {
			log.info("Skipped reaper cycle (sessions collected by peer already). Details: {}", ex.getMessage());
		}
		catch (InterruptedException ex) {
			log.info("Skipped reaper cycle");
			Thread.currentThread().interrupt(); // restore interrupt state
		}
		catch (Exception ex) {
			globalExceptionHandler.logException(ex);
		}
	}

	private long reapExpiredSessions(Instant currentTime) {
		var currentTimestamp = Timestamp.from(currentTime);
		var deleted = stateCacheRepository.deleteAllInBatchByExpirationTimestampBefore(currentTimestamp);
		log.debug("Deleted {} records expired {}", deleted, currentTimestamp);
		return deleted;
	}

	private long reapExpiringSessions(Instant currentTime, long numEntries) {
		long collected = 0;
		int targetMaxEntries = trustBrokerProperties.getStateCache().getTargetMaxEntries();
		if (numEntries > targetMaxEntries) {
			log.error("Too many entries for one reap cycle. Details: numEntries={} > targetMaxEntries={}",
					numEntries, targetMaxEntries);
			// delete not yet expired sessions
			var minLifetimeMillis = TimeUnit.SECONDS.toMillis(trustBrokerProperties.getStateCache().getMinSessionLifetimeSec());
			// SSO should be longer
			// for SSO groups with different timeouts this means that the default should be about the max of all groups
			var sessionLifetimeMillis = TimeUnit.SECONDS.toMillis(
					Math.max(trustBrokerProperties.getSsoSessionLifetimeSec(), trustBrokerProperties.getSessionLifetimeSec()));
			var keepSessionForMillis = sessionLifetimeMillis;
			do {
				// if session expires lifetime minus a fraction of the lifetime in the future up to configured minimum lifetime
				// i.e. keep for 1/2 lifetime, 1/4 lifetime, 1/8 lifetime, ...
				keepSessionForMillis /= 2;
				if (keepSessionForMillis <= minLifetimeMillis) {
					log.error("Aborting reaping session lifetime time limit {}s is reached while there are still {} entries",
							trustBrokerProperties.getStateCache().getMinSessionLifetimeSec(), numEntries);
					break;
				}
				// those sessions expire at now plus: 1/2 lifetime, 3/4 lifetime, 7/8 lifetime etc.
				var expirationTimeMillis = currentTime.plusMillis(sessionLifetimeMillis).minusMillis(keepSessionForMillis);
				var expirationTimestamp = Timestamp.from(expirationTimeMillis);
				var deleted = stateCacheRepository.deleteAllInBatchByExpirationTimestampBefore(expirationTimestamp);
				numEntries -= deleted;
				collected += deleted;
				log.debug("Deleted {} entries expiring after {}, {} remaining", deleted, expirationTimestamp, numEntries);
				// no need to get the precise count from the DB (even if this is not transactional):
			} while (numEntries > targetMaxEntries);
		}
		return collected;
	}

}
