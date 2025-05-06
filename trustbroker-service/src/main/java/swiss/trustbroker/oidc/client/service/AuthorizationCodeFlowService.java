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

package swiss.trustbroker.oidc.client.service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.exception.GlobalExceptionHandler;
import swiss.trustbroker.federation.xmlconfig.Certificates;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.Scope;
import swiss.trustbroker.oidc.client.dto.OpenIdProviderConfiguration;
import swiss.trustbroker.oidc.client.util.OidcClientUtil;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.util.ApiSupport;

/**
 * OIDC client for Authorization Code Flow.
 * 
 * Note: With 1.9.0 this feature is still unfinished, some parts to be completed in the NEXT release marked as such.
 */
@Component
@AllArgsConstructor
@Slf4j
public class AuthorizationCodeFlowService {

	// NEXT: improve cache
	private static final Map<String, OpenIdProviderConfiguration> OIDC_CONFIGURATIONS = new ConcurrentHashMap<>();

	private final RelyingPartyDefinitions relyingPartyDefinitions;

	private final GlobalExceptionHandler globalExceptionHandler;

	private final ApiSupport apiSupport;

	private final TrustBrokerProperties trustBrokerProperties;

	// fire /authorize
	public String redirectUserWithRequest(ClaimsParty claimsParty, StateData stateData) {
		var client = getOidcClient(claimsParty);
		var configuration = getOidcConfiguration(claimsParty, client);
		var scopes = client.hasScopes() ?
				client.getScopes().getScopeList() :
				Scope.defaultNames();
		var responseUrl = apiSupport.getOidcResponseApi(client.getRealm());
		// NEXT: ForceAuthn / prompt
		var authorizeUrl = OidcClientUtil.buildCodeFlowAuthorizationUrl(client, configuration, stateData, scopes, responseUrl);
		log.info("OIDC authorization code flow for cpIssuerId={} clientId={} sessionId={} "
						+ "redirecting to authorizationRequest=\"{}\"",
				claimsParty.getId(), client.getId(), stateData.getId(), authorizeUrl);
		return authorizeUrl.toString();
	}

	public void handleCpResponse(String realm, String code, ClaimsParty claimsParty, StateData stateData) {
		log.info("Processing code response for sessionId={} realm={} not yet implemented", stateData.getId(), realm);
		var client = getOidcClient(claimsParty);
		// realm should match, but technically and security-wise not relevant
		if (realm != null && !realm.equals(client.getRealm())) {
			log.warn("Inbound realm={} does not match clientId={} clientRealm={} for sessionId={}",
					realm, client.getId(), client.getRealm(), stateData.getId());
		}
		// fetch tokens (back-channel):
		var configuration = getOidcConfiguration(claimsParty, client);
		var tokenUri = configuration.getTokenEndpoint();
		var responseUrl = apiSupport.getOidcResponseApi(client.getRealm());
		var tokenResponse = OidcClientUtil.fetchTokens(claimsParty, client, configuration, trustBrokerProperties, tokenUri,
				responseUrl, code);
		var idToken = tokenResponse.get(OidcUtil.TOKEN_RESPONSE_ID_TOKEN);
		if (!(idToken instanceof String idTokenString)) {
			throw new RequestDeniedException(
					String.format("Did not receive OIDC ID token from client=%s tokenUri=%s", client.getId(), tokenUri));
		}
		var claims = OidcUtil.verifyJwtToken(idTokenString, configuration.getJwkSet(), client.getId());
		log.debug("OIDC ID client={} tokenUri={} claims={}", client.getId(), tokenUri, claims);
		validateClaims(claims, client);
		var cpResponse = buildCpResponseFromClaims(claimsParty, claims);
		log.info("OIDC ID client={} returned claims={}", client.getId(), cpResponse);
		// NEXT: audit
		stateData.setCpResponse(cpResponse);
	}

	private static void validateClaims(JWTClaimsSet claims, OidcClient client) {
		var audience = claims.getAudience();
		if (!audience.contains(client.getId())) {
			throw new RequestDeniedException(
					String.format("Did not receive OIDC ID token from client=%s aud=%s", client.getId(), audience));
		}
		var authorizedParty = claims.getClaim(OidcUtil.OIDC_AUTHORIZED_PARTY);
		if (authorizedParty != null && !authorizedParty.equals(client.getId())) {
			throw new RequestDeniedException(
					String.format("Did not receive OIDC ID token from client=%s azp=%s", client.getId(), authorizedParty));
		}
		// NEXT: verify iat, exp, iss
	}

	private static CpResponse buildCpResponseFromClaims(ClaimsParty claimsParty, JWTClaimsSet claims) {
		Map<Definition, List<String>> attributes = mapClaimsToAttributes(claimsParty, claims);
		return CpResponse.builder()
								   .issuer(claims.getIssuer())
								   .nameId(claims.getSubject())
								   .claims(claims.getClaims())
								   .attributes(attributes)
								   .build();
	}

	private static Map<Definition, List<String>> mapClaimsToAttributes(ClaimsParty claimsParty, JWTClaimsSet claims) {
		Map<Definition, List<String>> attributes = new HashMap<>();
		if (claimsParty.getAttributesSelection() == null
						|| CollectionUtils.isEmpty(claimsParty.getAttributesSelection().getDefinitions())) {
			return attributes;
		}
		for (var claim : claims.getClaims().entrySet()) {
			for (var definition : claimsParty.getAttributesSelection().getDefinitions()) {
				if (definition.equalsByNameOrNamespace(claim.getKey())) {
					attributes.put(definition, convertClaimValue(claim.getValue()));
				}
			}
		}
		return attributes;
	}

	private static List<String> convertClaimValue(Object claimValue) {
		List<String> values = new ArrayList<>();
		if (claimValue instanceof String claimString) {
			values.add(claimString);
		}
		else if (claimValue instanceof List<?> claimList) {
			for (var singleValue : claimList) {
				values.add(singleValue.toString());
			}
		}
		// NEXT: apply mappers to handle other types
		else if (claimValue != null) {
			values.add(claimValue.toString());
		}
		return values;
	}

	// token check by backend
	public JWKSet getKeySet(ClaimsParty claimsParty, String expectedKid) {
		var keySet = getOidcConfiguration(claimsParty).getJwkSet();
		if (expectedKid != null && keySet.getKeyByKeyId(expectedKid) == null) {
			// single retry to check, if we missed a key rotation
			// NEXT minimal caching time (DOS prevention)
			log.info("Unknown kid={} from cpIssuer={}, try retrieving JWKs once", expectedKid, claimsParty.getId());
			var config = reloadConfiguration(getOidcClient(claimsParty), claimsParty.getCertificates());
			keySet = config.getJwkSet();
		}
		return keySet;
	}

	// ClaimsParty => OidcClient
	private static OidcClient getOidcClient(ClaimsParty claimsParty) {
		if (claimsParty.getOidc() == null) {
			throw new TechnicalException(String.format("Invalid ClaimsParty id=%s (not an Oidc Client)",
					claimsParty.getId()));
		}
		var oidcClientCount = claimsParty.getOidc().getClients().size();
		if (oidcClientCount != 1) {
			throw new TechnicalException(String.format("Invalid ClaimsParty id=%s count=%s",
					claimsParty.getId(), oidcClientCount));
		}
		return claimsParty.getOidc().getClients().get(0);
	}

	// ClaimsParty => OidcClient => OidcConfiguration (from OpenId provider)
	private OpenIdProviderConfiguration getOidcConfiguration(ClaimsParty claimsParty) {
		var oidcClient = getOidcClient(claimsParty);
		return getOidcConfiguration(claimsParty, oidcClient);
	}

	private OpenIdProviderConfiguration getOidcConfiguration(ClaimsParty claimsParty, OidcClient oidcClient) {
		var oidcClientConfig = OIDC_CONFIGURATIONS.get(oidcClient.getId());
		if (oidcClientConfig == null) {
			oidcClientConfig = reloadConfiguration(oidcClient, claimsParty.getCertificates());
			OIDC_CONFIGURATIONS.put(oidcClient.getId(), oidcClientConfig);
		}
		return oidcClientConfig;
	}

	// cache miss or missing JWK, trigger a refresh
	private OpenIdProviderConfiguration reloadConfiguration(OidcClient client, Certificates certificates) {
		return OidcClientUtil.fetchProviderMetadata(client, certificates, trustBrokerProperties);
	}

	// On startup or scheduled reload all OIDC configuration endpoints
	@Scheduled(initialDelay = 0, fixedDelay=Long.MAX_VALUE)
	public void initConfiguration() {
		refreshConfigurations();
	}

	@Scheduled(cron = "${trustbroker.config.oidc.syncSchedule}")
	public void refreshConfigurations() {
		var loadCount = 0;
		var start = System.currentTimeMillis();
		var claimsParties = relyingPartyDefinitions
				.getClaimsProviderSetup()
				.getClaimsParties()
				.stream()
				.filter(ClaimsParty::useOidc)
				.toList();
		log.info("OIDC client configuration update for claimsPartyCount={}", claimsParties.size());
		for (var claimsParty : claimsParties) {
			try {
				var oidcClient = getOidcClient(claimsParty);
				var config = reloadConfiguration(oidcClient, claimsParty.getCertificates());
				if (config != null) {
					OIDC_CONFIGURATIONS.put(oidcClient.getId(), config);
					++loadCount;
				}
			}
			catch (RuntimeException ex) {
				globalExceptionHandler.logException(ex);
			}
		}

		var dTms = System.currentTimeMillis() - start;
		var failCount = claimsParties.size() - loadCount;
		log.info("OIDC client configuration update done for claimsPartyCount={} in dtMs={} with failCount={}",
				claimsParties.size(), dTms, failCount);
	}

}
