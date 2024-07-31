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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static swiss.trustbroker.util.SessionTimeConfiguration.EXPIRATION_INSTANT;
import static swiss.trustbroker.util.SessionTimeConfiguration.EXPIRATION_INSTANT_SSO;
import static swiss.trustbroker.util.SessionTimeConfiguration.PAST_INSTANT;
import static swiss.trustbroker.util.SessionTimeConfiguration.SESSION_LIFETIME_SECS;
import static swiss.trustbroker.util.SessionTimeConfiguration.SESSION_LIFETIME_SECS_SSO;
import static swiss.trustbroker.util.SessionTimeConfiguration.START_INSTANT;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Collections;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ContextConfiguration;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.StateCacheProperties;
import swiss.trustbroker.exception.GlobalExceptionHandler;
import swiss.trustbroker.sessioncache.dto.LifecycleState;
import swiss.trustbroker.sessioncache.dto.SsoSessionParticipant;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.sessioncache.dto.StateEntity;
import swiss.trustbroker.sessioncache.repo.StateCacheRepository;
import swiss.trustbroker.util.SessionTimeConfiguration;

@SpringBootTest
@ContextConfiguration(classes = { SessionTimeConfiguration.class, StateCacheService.class })
class StateCacheServiceTest {

	@MockBean
	private StateCacheRepository stateCacheRepository;

	@MockBean
	private TrustBrokerProperties trustBrokerProperties;

	@MockBean
	private GlobalExceptionHandler globalExceptionHandler;

	@MockBean
	private StateCacheProperties stateCacheProperties;

	@Autowired
	private StateCacheService cacheService;

	@BeforeEach
	void setUp() {
		// configs
		doReturn(SESSION_LIFETIME_SECS).when(trustBrokerProperties).getSessionLifetimeSec();
		doReturn(SESSION_LIFETIME_SECS).when(trustBrokerProperties).getSessionLifetimeSec(false);
		doReturn(SESSION_LIFETIME_SECS_SSO).when(trustBrokerProperties).getSsoSessionLifetimeSec();
		doReturn(SESSION_LIFETIME_SECS_SSO).when(trustBrokerProperties).getSessionLifetimeSec(true);
		doReturn(stateCacheProperties).when(trustBrokerProperties).getStateCache();
		doReturn(10).when(stateCacheProperties).getTargetMaxEntries();
		doReturn(60).when(stateCacheProperties).getMinSessionLifetimeSec();
		doReturn(1).when(stateCacheProperties).getReapMaxDelaySec();
	}

	private StateEntity mockStateEntity(LifecycleState lifecycleState) {
		var entity = new StateEntity();
		entity.setId("entityId");
		entity.setSpSessionId("spId");
		entity.setJsonData("{\"id\":\"entityId\",\"lifecycle\":{\"lifecycleState\":\"" + lifecycleState + "\"}}");
		entity.setExpirationTimestamp(Timestamp.from(EXPIRATION_INSTANT));
		doReturn(Optional.of(entity)).when(stateCacheRepository).findById(entity.getId());
		return entity;
	}

	private StateData createStateData(String id, String spId) {
		var spStateData = StateData.builder()
				.id(spId)
				.build();
		var data = StateData.builder()
				.id(id)
				.spStateData(spStateData)
				.build();
		return data;
	}

	@Test
	void save() {
		var data = createStateData("testId", "spId");
		this.cacheService.save(data, "Test");
		ArgumentCaptor<StateEntity> captor = ArgumentCaptor.forClass(StateEntity.class);
		verify(stateCacheRepository).save(captor.capture());
		assertThat(captor.getValue().getId(), is(data.getId()));
		assertThat(captor.getValue().getExpirationTimestamp(), is(Timestamp.from(EXPIRATION_INSTANT)));
		assertThat(data.getLifecycle().getLifecycleState(), is(LifecycleState.INIT));
		assertThat(data.getSpStateData().getLifecycle().getLifecycleState(), is(LifecycleState.INIT));
		assertThat(data.getLifecycle().getInitTime(), is(Timestamp.from(START_INSTANT)));
	}

	@Test
	void saveWithoutLifecycle() {
		var data = createStateData("testId", "spId");
		this.cacheService.save(data, "Test");
		assertThat(data.getLifecycle().getLifecycleState(), is(LifecycleState.INIT));
		assertThat(data.getSpStateData().getLifecycle().getLifecycleState(), is(LifecycleState.INIT));
		assertThat(data.getLifecycle().getInitTime(), is(Timestamp.from(START_INSTANT)));
	}

	@Test
	void saveWithoutLifecycleInSpState() {
		var data = createStateData("testId", "spId");
		data.getLifecycle().setLifecycleState(LifecycleState.ESTABLISHED);
		this.cacheService.save(data, "Test");
		assertThat(data.getLifecycle().getLifecycleState(), is(LifecycleState.ESTABLISHED));
		assertThat(data.getSpStateData().getLifecycle().getLifecycleState(), is(LifecycleState.INIT));
	}

	@Test
	void saveSsoEstablished() {
		var data = createStateData("testId", "spId");
		verifyStateAfterSaveSso(data, EXPIRATION_INSTANT_SSO);
		assertThat(data.getLifecycle().getSsoEstablishedTime(), is(Timestamp.from(START_INSTANT)));
	}

	@Test
	void saveSsoEstablishedWithGroupIdleTimeout() {
		var data = createStateData("testId1", "spId1");
		var sessionIdleTimeSecs = 120;
		data.addSsoParticipant(new SsoSessionParticipant("rpIssuer1", "cpIssuer1", "acs1", null, null));
		data.getSsoState().setMaxIdleTimeSecs(sessionIdleTimeSecs);
		data.getSsoState().setSsoGroupName("Group1");
		verifyStateAfterSaveSso(data, START_INSTANT.plusSeconds(sessionIdleTimeSecs));
		assertThat(data.getLifecycle().getSsoEstablishedTime(), is(Timestamp.from(START_INSTANT)));
	}

	@Test
	void saveSsoEstablishedWithGroupTimeouts() {
		var data = createStateData("testId1", "spId1");
		var sessionLifeTimeSecs = 180;
		var sessionStart = START_INSTANT.minusSeconds(sessionLifeTimeSecs / 2);
		data.getLifecycle().setSsoEstablishedTime(Timestamp.from(sessionStart));
		var sessionIdleTimeSecs = 120;
		data.addSsoParticipant(new SsoSessionParticipant("rpIssuer1", "cpIssuer1", "acs1", null, null));
		data.getSsoState().setMaxIdleTimeSecs(sessionIdleTimeSecs);
		data.getSsoState().setMaxSessionTimeSecs(sessionLifeTimeSecs);
		data.getSsoState().setSsoGroupName("Group1");
		verifyStateAfterSaveSso(data, sessionStart.plusSeconds(sessionLifeTimeSecs));
		// must not change:
		assertThat(data.getLifecycle().getSsoEstablishedTime(), is(Timestamp.from(sessionStart)));
	}

	private void verifyStateAfterSaveSso(StateData data, Instant expirationTimestamp) {
		data.getLifecycle().setLifecycleState(LifecycleState.ESTABLISHED);
		data.initializedSsoState();
		this.cacheService.save(data, "Test");
		ArgumentCaptor<StateEntity> captor = ArgumentCaptor.forClass(StateEntity.class);
		verify(stateCacheRepository).save(captor.capture());
		assertThat(captor.getValue().getId(), is(data.getId()));
		assertThat(captor.getValue().getExpirationTimestamp(), is(Timestamp.from(expirationTimestamp)));
		assertThat(data.getLifecycle().getInitTime(), is(Timestamp.from(START_INSTANT)));
	}

	@Test
	void findOptional() {
		var entity = mockStateEntity(LifecycleState.INIT);
		var result = this.cacheService.findOptional(entity.getId(), "Test");
		assertThat(result.isPresent(), is(true));
		assertThat(result.get().getId(), is(entity.getId()));
	}

	@ParameterizedTest
	@CsvSource(value = "null,12345", nullValues = "null")
	void findOptionalMissing(String id) {
		var result = this.cacheService.findOptional(id, "Test");
		assertThat(result.isEmpty(), is(true));
	}

	@Test
	void findById() {
		var entity = mockStateEntity(LifecycleState.INIT);
		StateData result = this.cacheService.find(entity.getId(), "Test");
		assertThat(result.getId(), is(entity.getId()));
	}

	@Test()
	void findByIdMissing() {
		doReturn(Optional.empty()).when(stateCacheRepository).findById("testId");
		assertThrows(RequestDeniedException.class, () -> this.cacheService.find("testId", "Test"));
	}

	@Test
	void findBySpId() {
		var entity = mockStateEntity(LifecycleState.ESTABLISHED);
		doReturn(Collections.singletonList(entity)).when(stateCacheRepository).findBySpSessionId(entity.getSpSessionId());
		var result = this.cacheService.findBySpId(entity.getSpSessionId(), "Test");
		assertThat(result.isPresent(), is(true));
		assertThat(result.get().getId(), is(entity.getId()));
	}

	@Test
	void findBySpIdNull() {
		var result = this.cacheService.findBySpId(null, null);
		assertThat(result.isEmpty(), is(true));
	}

	@Test
	void findByIdNull() {
		assertThrows(RequestDeniedException.class, () -> this.cacheService.find(null, "Test"));
	}

	@Test
	void findBySpIdInvalid() {
		var entity = mockStateEntity(LifecycleState.EXPIRED);
		doReturn(Collections.singletonList(entity)).when(stateCacheRepository).findBySpSessionId(entity.getSpSessionId());
		var result = this.cacheService.findBySpId(entity.getSpSessionId(), "Test");
		assertThat(result.isPresent(), is(false));
	}

	@Test
	void findBySpIdMissing() {
		doReturn(Collections.emptyList()).when(stateCacheRepository).findBySpSessionId("missingId");
		var result = this.cacheService.findBySpId("missingId", "Test");
		assertThat(result.isPresent(), is(false));
	}

	@Test
	void findValidStateMissing() {
		doReturn(Collections.emptyList()).when(stateCacheRepository).findBySpSessionId("missingId");
		var result = this.cacheService.findValidState("missingId", "Test");
		assertThat(result.isPresent(), is(false));
	}

	@Test
	void findValidStateInvalid() {
		var entity = mockStateEntity(LifecycleState.EXPIRED);
		var result = this.cacheService.findValidState(entity.getId(), "Test");
		assertThat(result.isPresent(), is(false));
	}

	@Test
	void findValidStateExpired() {
		var entity = mockStateEntity(LifecycleState.INIT);
		entity.setExpirationTimestamp(Timestamp.from(PAST_INSTANT));
		var result = this.cacheService.findValidState(entity.getId(), "Test");
		assertThat(result.isPresent(), is(false));
	}

	@Test
	void findValidStateValid() {
		var entity = mockStateEntity(LifecycleState.INIT);
		var result = this.cacheService.findValidState(entity.getId(), "Test");
		assertThat(result.isPresent(), is(true));
		assertThat(result.get().getId(), is(entity.getId()));
	}

	@Test
	void findMandatoryValidStateValid() {
		var entity = mockStateEntity(LifecycleState.INIT);
		var result = this.cacheService.findMandatoryValidState(entity.getId(), "Test");
		assertThat(result.getId(), is(entity.getId()));
	}

	@Test
	void findMandatoryValidStateExpired() {
		var entity = mockStateEntity(LifecycleState.EXPIRED);
		var id = entity.getId();
		assertThrows(RequestDeniedException.class, () -> this.cacheService.findMandatoryValidState(id, "Test"));
	}

	@Test
	void invalidate() {
		var entity = mockStateEntity(LifecycleState.INIT);
		var data = createStateData(entity.getId(), entity.getSpSessionId());
		this.cacheService.invalidate(data, this.getClass().getSimpleName());
		assertStateAfterInvalidate(data);
		assertThat(data.getLifecycle().getReauthTime(), is(nullValue()));
		verify(stateCacheRepository).save(entity);
	}

	@Test
	void invalidateAfterAuth() {
		var entity = mockStateEntity(LifecycleState.INIT);
		var data = createStateData(entity.getId(), entity.getSpSessionId());
		this.cacheService.invalidate(data, true, "Test");
		assertStateAfterInvalidate(data);
		assertThat(data.getLifecycle().getReauthTime(), is(Timestamp.from(START_INSTANT)));
		verify(stateCacheRepository).save(entity);
	}

	private void assertStateAfterInvalidate(StateData data) {
		assertThat(data.isValid(), is(false));
		assertThat(data.getLifecycle().getLifecycleState(), is(LifecycleState.EXPIRED));
		assertThat(data.getSpStateData().isValid(), is(false));
		assertThat(data.getLifecycle().getExpiredTime(), is(Timestamp.from(START_INSTANT)));
	}

	@Test
	void ssoEstablished() {
		var entity = mockStateEntity(LifecycleState.INIT);
		var data = createStateData(entity.getId(), entity.getSpSessionId());
		this.cacheService.ssoEstablished(data, "Test");
		validateSsoSession(data, entity);
		assertThat(data.getLifecycle().getSsoEstablishedTime(), is(Timestamp.from(START_INSTANT)));
		assertThat(data.getLifecycle().getReauthTime(), is(nullValue()));
	}

	@Test
	void ssoEstablishedReauth() {
		var entity = mockStateEntity(LifecycleState.INIT);
		var data = createStateData(entity.getId(), entity.getSpSessionId());
		var ssoEstablishedTime = Timestamp.from(START_INSTANT.minusSeconds(30));
		data.getLifecycle().setSsoEstablishedTime(ssoEstablishedTime);
		this.cacheService.ssoEstablished(data, "Test");
		validateSsoSession(data, entity);
		assertThat(data.getLifecycle().getSsoEstablishedTime(), is(ssoEstablishedTime));
		assertThat(data.getLifecycle().getReauthTime(), is(Timestamp.from(START_INSTANT)));
	}

	private void validateSsoSession(StateData data, StateEntity entity) {
		assertThat(data.isValid(), is(true));
		assertThat(data.getLifecycle().getLifecycleState(), is(LifecycleState.ESTABLISHED));
		assertThat(data.getSpStateData().isValid(), is(true));
		assertThat(data.getSpStateData().getLifecycle().getLifecycleState(), is(LifecycleState.ESTABLISHED));
		verify(stateCacheRepository).save(entity);
	}

	@Test
	void ssoEstablishedInvalid() {
		var entity = mockStateEntity(LifecycleState.EXPIRED);
		var data = createStateData(entity.getId(), entity.getSpSessionId());
		data.getLifecycle().setLifecycleState(LifecycleState.EXPIRED);
		assertThrows(RequestDeniedException.class, () -> this.cacheService.ssoEstablished(data, "Test"));
	}

	@Test
	void reapBelowLimit() {
		doReturn(5).when(stateCacheRepository).deleteAllInBatchByExpirationTimestampBefore(any());
		doReturn(10l).when(stateCacheRepository).count();

		this.cacheService.reap();

		verify(stateCacheRepository, times(1)).deleteAllInBatchByExpirationTimestampBefore(
				Timestamp.from(START_INSTANT));
		verify(stateCacheRepository, times(1)).count();
		verifyNoMoreInteractions(stateCacheRepository);
	}

	@Test
	void reapOverLimit() {
		doReturn(4).when(stateCacheRepository).deleteAllInBatchByExpirationTimestampBefore(any());
		doReturn(15l).when(stateCacheRepository).count();
		doReturn(2).when(stateCacheRepository).deleteAllInBatchByExpirationTimestampBefore(any());

		this.cacheService.reap();

		verify(stateCacheRepository, times(1)).deleteAllInBatchByExpirationTimestampBefore(
				Timestamp.from(START_INSTANT));
		verify(stateCacheRepository, times(1)).count();
		// 15 sessions
		verify(stateCacheRepository, times(1)).deleteAllInBatchByExpirationTimestampBefore(
				Timestamp.from(EXPIRATION_INSTANT_SSO.minusMillis(TimeUnit.HOURS.toMillis(12))));
		// 13 sessions
		verify(stateCacheRepository, times(1)).deleteAllInBatchByExpirationTimestampBefore(
				Timestamp.from(EXPIRATION_INSTANT_SSO.minusMillis(TimeUnit.HOURS.toMillis(6))));
		// 11 sessions
		verify(stateCacheRepository, times(1)).deleteAllInBatchByExpirationTimestampBefore(
				Timestamp.from(EXPIRATION_INSTANT_SSO.minusMillis(TimeUnit.HOURS.toMillis(3))));
		// 9 sessions
		verifyNoMoreInteractions(stateCacheRepository);
	}

	@Test
	void reapNeverReachesLimit() {
		doReturn(4).when(stateCacheRepository).deleteAllInBatchByExpirationTimestampBefore(any());
		doReturn(15l).when(stateCacheRepository).count();
		// no sessions ever reaped:
		doReturn(0).when(stateCacheRepository).deleteAllInBatchByExpirationTimestampBefore(any());

		this.cacheService.reap();

		verify(stateCacheRepository, times(1)).deleteAllInBatchByExpirationTimestampBefore(
				Timestamp.from(START_INSTANT));
		verify(stateCacheRepository, times(1)).count();
		verify(stateCacheRepository, times(1)).deleteAllInBatchByExpirationTimestampBefore(
				Timestamp.from(EXPIRATION_INSTANT_SSO.minusMillis(TimeUnit.HOURS.toMillis(12))));
		verify(stateCacheRepository, times(1)).deleteAllInBatchByExpirationTimestampBefore(
				Timestamp.from(EXPIRATION_INSTANT_SSO.minusMillis(TimeUnit.HOURS.toMillis(6))));
		verify(stateCacheRepository, times(1)).deleteAllInBatchByExpirationTimestampBefore(
				Timestamp.from(EXPIRATION_INSTANT_SSO.minusMillis(TimeUnit.HOURS.toMillis(3))));
		verify(stateCacheRepository, times(1)).deleteAllInBatchByExpirationTimestampBefore(
				Timestamp.from(EXPIRATION_INSTANT_SSO.minusMillis(TimeUnit.MINUTES.toMillis(90))));
		verify(stateCacheRepository, times(1)).deleteAllInBatchByExpirationTimestampBefore(
				Timestamp.from(EXPIRATION_INSTANT_SSO.minusMillis(TimeUnit.MINUTES.toMillis(45))));
		verify(stateCacheRepository, times(1)).deleteAllInBatchByExpirationTimestampBefore(
				Timestamp.from(EXPIRATION_INSTANT_SSO.minusMillis(TimeUnit.SECONDS.toMillis(1350))));
		verify(stateCacheRepository, times(1)).deleteAllInBatchByExpirationTimestampBefore(
				Timestamp.from(EXPIRATION_INSTANT_SSO.minusMillis(TimeUnit.SECONDS.toMillis(675))));
		verify(stateCacheRepository, times(1)).deleteAllInBatchByExpirationTimestampBefore(
				Timestamp.from(EXPIRATION_INSTANT_SSO.minusMillis(337500l)));
		verify(stateCacheRepository, times(1)).deleteAllInBatchByExpirationTimestampBefore(
				Timestamp.from(EXPIRATION_INSTANT_SSO.minusMillis(168750l)));
		verify(stateCacheRepository, times(1)).deleteAllInBatchByExpirationTimestampBefore(
				Timestamp.from(EXPIRATION_INSTANT_SSO.minusMillis(84375l)));
		// must stop at MinSessionLifetimeSec

		verifyNoMoreInteractions(stateCacheRepository);
	}

}
