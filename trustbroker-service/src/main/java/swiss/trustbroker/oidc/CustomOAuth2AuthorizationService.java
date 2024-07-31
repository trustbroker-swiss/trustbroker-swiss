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

package swiss.trustbroker.oidc;

import java.sql.Timestamp;
import java.sql.Types;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

import jakarta.persistence.OptimisticLockException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.ConcurrencyFailureException;
import org.springframework.jdbc.core.ArgumentPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.SqlParameterValue;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.exception.GlobalExceptionHandler;

// JDBC based token reaper collecting all tokens from the spring-authorization-server token storage.
// Implementation needs to stay aligned with the JdbcOAuth2AuthorizationService.
// Note that the table is protected by the federated login exchange as the first token stored is the
// code token retained during the login exchange in the user-agent and stored for the first time _after_
// the user has actually logged in.
@Slf4j
@Service
@AllArgsConstructor
public class CustomOAuth2AuthorizationService {

	private static final String TOKEN_TABLE = "oauth2_authorization";

	private static final String DELETE_EXPIRED_TOKENS
			= "DELETE FROM " + TOKEN_TABLE + " WHERE access_token_expires_at < ? AND authorization_code_expires_at < ?";

	private static final String DELETE_AUTHORIZATION_BY_CLIENTID_PRINCIPAL
			= "DELETE FROM " + TOKEN_TABLE + " WHERE registered_client_id = ? AND principal_name = ?";

	private final TrustBrokerProperties trustBrokerProperties;

	private final GlobalExceptionHandler globalExceptionHandler;

	private final Clock clock;

	private final JdbcOperations jdbcOperations;

	@SuppressWarnings("java:S2245") // use of unsecure random just for randomizing run time between PODs
	@Scheduled(cron = "${trustbroker.config.oidc.reapSchedule}")
	public void deleteExpiredTokens() {
		try {
			var randomDelaySec = trustBrokerProperties.getStateCache().getReapMaxDelaySec();
			var randomDelayMs = ThreadLocalRandom.current().nextInt(randomDelaySec > 0 ? randomDelaySec * 1000 : 1);
			Thread.sleep(randomDelayMs);

			var start = clock.instant();
			var currentTimestamp = Timestamp.from(start);
			log.info("Start reaping token store (delayMs={})...", randomDelayMs);
			SqlParameterValue[] parameters = new SqlParameterValue[] {
					new SqlParameterValue(Types.TIMESTAMP, currentTimestamp),
					new SqlParameterValue(Types.TIMESTAMP, currentTimestamp)
			};
			PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters);
			long expired = jdbcOperations.update(DELETE_EXPIRED_TOKENS, pss);

			// result with tuning recommendations when reaper needs to collect too many sessions
			if (log.isWarnEnabled()) {
				var elapsed = Duration.between(start, clock.instant()).toMillis();
				var msg = String.format("Completed reaping TokenCache in dTms=%d expiredTokens=%d", elapsed, expired);
				if (elapsed < trustBrokerProperties.getStateCache().getReapWarnThresholdMs()) {
					log.info(msg);
				}
				else {
					log.warn(msg + " (HINT: Check long-term storage of tokens and cleanup oauth2_authorization table)");
				}
			}
		}
		catch (OptimisticLockException | ConcurrencyFailureException ex) {
			log.info("Skipped token store reaper cycle (sessions collected by peer already). Details: {}",
					ex.getMessage());
		}
		catch (InterruptedException ex) {
			log.info("Skipped token store reaper cycle");
			Thread.currentThread().interrupt(); // restore interrupt state
		}
		catch (Exception ex) {
			globalExceptionHandler.logException(ex);
		}
	}

	public void deleteAuthorizationByClientId(String clientId, String principalName) {
		log.debug("Delete tokens for ClientID={}", clientId);

		List<SqlParameterValue> paramsList = new ArrayList<>();
		paramsList.add(new SqlParameterValue(Types.CHAR, clientId));
		paramsList.add(new SqlParameterValue(Types.CHAR, principalName));
		SqlParameterValue[] parameters = new SqlParameterValue[paramsList.size()];
		paramsList.toArray(parameters);

		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters);
		long deleted = jdbcOperations.update(DELETE_AUTHORIZATION_BY_CLIENTID_PRINCIPAL, pss);
		log.debug("Deleted tokens={} for ClientID={} PrincipalName={}", deleted, clientId, principalName);
	}

}
