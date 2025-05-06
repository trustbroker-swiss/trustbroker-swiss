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

package swiss.trustbroker.oidc.client.util;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.nimbusds.jose.jwk.JWKSet;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import swiss.trustbroker.common.config.KeystoreProperties;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.exception.TrustBrokerException;
import swiss.trustbroker.common.tracing.Traced;
import swiss.trustbroker.common.util.HttpUtil;
import swiss.trustbroker.common.util.JsonUtil;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.AuthorizationGrantType;
import swiss.trustbroker.federation.xmlconfig.Certificates;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.oidc.client.dto.OpenIdProviderConfiguration;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.util.CertificateUtil;

/**
 * Client-side OIDC functionality.
 */
@Slf4j
public class OidcClientUtil {

	// fields in metadata

	public static final String METADATA_AUTHORIZATION_ENDPOINT = "authorization_endpoint";

	public static final String METADATA_JWKS_URI = "jwks_uri";

	public static final String METADATA_TOKEN_ENDPOINT = "token_endpoint";

	public static final String METADATA_TOKEN_AUTH_METHODS = "token_endpoint_auth_methods_supported";

	private OidcClientUtil() {}

	@Traced
	public static OpenIdProviderConfiguration fetchProviderMetadata(OidcClient client, Certificates certificates,
			TrustBrokerProperties trustBrokerProperties) {
		var configurationUrl = getConfigurationUrl(client);
		try {
			var metadataUri = WebUtil.getValidatedUri(configurationUrl);
			if (metadataUri == null) {
				throw new TechnicalException(String.format("oidcClientId=%s has missing or invalid configurationUrl=%s",
						client.getId(), configurationUrl));
			}
			var httpClient = createHttpClient(client, certificates, trustBrokerProperties, metadataUri);

			// fetch metadata
			var start = System.currentTimeMillis();
			var metadataResponse = HttpUtil.getHttpResponseString(httpClient, metadataUri);
			if (metadataResponse.isEmpty()) {
				throw new TechnicalException(String.format("oidcClientId=%s failed to fetch configurationUrl=%s",
						client.getId(), configurationUrl));
			}
			var result = parseOidcMetadata(metadataResponse.get(), client);
			log.debug("oidcClient={} configurationUrl={} returned result={}", client.getId(), configurationUrl, result);
			var jwksResponse = HttpUtil.getHttpResponseStream(httpClient, result.getJwkEndpoint());
			if (jwksResponse.isEmpty()) {
				throw new TechnicalException(String.format("oidcClientId=%s failed to fetch configurationUrl=%s",
						client.getId(), configurationUrl));
			}
			var jwkSet = JWKSet.load(jwksResponse.get());
			result.setJwkSet(jwkSet);

			// done
			var dTms = System.currentTimeMillis() - start;
			log.info("Loaded oidcClientId={} from configurationUrl={} in dTms={} : result={}",
					client.getId(), configurationUrl, dTms, result);
			return result;
		}
		catch (TrustBrokerException ex) {
			throw ex;
		}
		catch (IOException | ParseException ex) {
			throw new TechnicalException(String.format("oidcClientId=%s failed to fetch configurationUrl=%s message=%s",
					client.getId(), configurationUrl, ex.getMessage()), ex);
		}
	}

	private static HttpClient createHttpClient(OidcClient client, Certificates certificates,
			TrustBrokerProperties trustBrokerProperties, URI targetUri) {
		var proxyUri = getProxyUri(client, trustBrokerProperties);
		var truststore = trustBrokerProperties.getOidc().getTruststore();
		if (certificates.getBackendTruststore() != null) {
			truststore = CertificateUtil.toKeystoreProperties(certificates.getBackendTruststore());
		}
		KeystoreProperties keystore = null;
		if (certificates.getBackendKeystore() != null	) {
			keystore = CertificateUtil.toKeystoreProperties(certificates.getBackendKeystore());
		}
		return HttpUtil.createHttpClient(targetUri.getScheme(), truststore, keystore,
				trustBrokerProperties.getKeystoreBasePath(), proxyUri, null);
	}

	private static OpenIdProviderConfiguration parseOidcMetadata(String jsonString, OidcClient oidcClient) {
		var metadataMap = JsonUtil.parseJsonObject(jsonString, false);
		var authorizationEndpoint = getUri(metadataMap, METADATA_AUTHORIZATION_ENDPOINT, oidcClient);
		var jwkEndpoint = getUri(metadataMap, METADATA_JWKS_URI, oidcClient);
		var tokenEndpoint = getUri(metadataMap, METADATA_TOKEN_ENDPOINT, oidcClient);
		var tokenAuthMethods = JsonUtil.getField(metadataMap, METADATA_TOKEN_AUTH_METHODS, List.class);
		var clientSecretBasic = tokenAuthMethods == null || tokenAuthMethods.contains(
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue());
		var clientSecretPost = !clientSecretBasic && tokenAuthMethods != null && tokenAuthMethods.contains(
				ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue());
		return OpenIdProviderConfiguration.builder()
										  .authorizationEndpoint(authorizationEndpoint)
										  .jwkEndpoint(jwkEndpoint)
										  .tokenEndpoint(tokenEndpoint)
										  .clientSecretPost(clientSecretPost)
										  .build();
	}

	private static URI getUri(Map<String, Object> metadataMap, String key, OidcClient client) {
		var value = JsonUtil.getField(metadataMap, key, String.class);
		var uri = WebUtil.getValidatedUri(value);
		if (uri == null) {
			var configurationUrl = getConfigurationUrl(client);
			throw new TechnicalException(String.format(
					"oidcClientId=%s configurationUrl=%s has missing or invalid %s=%s",
					client.getId(), configurationUrl, key, value));
		}
		return uri;
	}

	private static String getConfigurationUrl(OidcClient client) {
		if (client.getProtocolEndpoints() == null) {
			return null;
		}
		return client.getProtocolEndpoints().getMetadataUrl();
	}

	private static URI getProxyUri(OidcClient client, TrustBrokerProperties trustBrokerProperties) {
		if (client.getProtocolEndpoints() == null) {
			return null;
		}
		var proxyUrl = client.getProtocolEndpoints().getProxyUrl();
		if (proxyUrl == null && trustBrokerProperties.getNetwork() != null) {
			proxyUrl = trustBrokerProperties.getNetwork().getProxyUrl();
		}
		if (StringUtils.isEmpty(proxyUrl)) {
			return null;
		}
		return WebUtil.getValidatedUri(proxyUrl);
	}

	public static URI buildCodeFlowAuthorizationUrl(OidcClient client, OpenIdProviderConfiguration providerConfiguration,
			StateData state, List<String> scopes, String redirectUri) {
		var endpoint = providerConfiguration.getAuthorizationEndpoint();
		var scopeString = String.join(" ", scopes);
		// audience not sent
		var queryString = "?response_type=code&response_mode=query"
				+ "&client_id=" + WebUtil.urlEncodeValue(client.getId())
				+ "&state=" + WebUtil.urlEncodeValue(state.getId())
				+ "&scope=" + WebUtil.urlEncodeValue(scopeString)
				+ "&nonce=" + WebUtil.urlEncodeValue(state.getOidcNonce())
				+ "&redirect_uri=" + WebUtil.urlEncodeValue(redirectUri);
		// concat as URI::resolve cuts the last part of path without trailing slash, e.g. trailing /authorize is lost
		var uri = WebUtil.getValidatedUri(endpoint.toString() + queryString);
		log.debug("OIDC authorization request to authorizationEndpoint={} for clientId={} state={} scope={} redirectUri={} "
						+ "is authorizationRequest=\"{}\"",
				endpoint, client.getId(), state.getId(), scopes, redirectUri, uri);
		return uri;
	}

	public static Map<String, Object> fetchTokens(ClaimsParty claimsParty, OidcClient client,
			OpenIdProviderConfiguration configuration, TrustBrokerProperties trustBrokerProperties, URI tokenUri,
			String responseUrl, String code) {
		var clientSecret = resolveClientSecret(client);
		String clientSecretPost = null;
		Map<String, String> headers = new HashMap<>();
		if (configuration.isClientSecretPost()) {
			clientSecretPost = clientSecret;
			log.debug("Using client_secret_post");
		}
		else {
			var authorization = OidcUtil.getBasicAuthorizationHeader(client.getId(), clientSecret);
			headers.put(HttpHeaders.AUTHORIZATION, authorization);
			log.debug("Using client_secret_basic");
		}
		var params = buildTokenRequestParameters(client, code, responseUrl, clientSecretPost);
		log.info("HTTP POST to tokenEndpoint={} responseUrl={} params={} not yet implemented", tokenUri, responseUrl, params);
		var httpClient = OidcClientUtil.createHttpClient(client, claimsParty.getCertificates(), trustBrokerProperties, tokenUri);
		var response = HttpUtil.getHttpFormPostString(httpClient, tokenUri, params, headers);
		if (response.isEmpty()) {
			throw new TechnicalException(String.format("oidcClientId=%s failed POST to tokenUri=%s",
					client.getId(), tokenUri));
		}
		return JsonUtil.parseJsonObject(response.get(), false);
	}

	private static Map<String, String> buildTokenRequestParameters(OidcClient client, String code,
			String redirectUri, String clientSecret) {
		Map<String, String> params = new HashMap<>();
		params.put(OidcUtil.CODE, code);
		params.put(OidcUtil.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.name().toLowerCase());
		params.put(OidcUtil.REDIRECT_URI, redirectUri);
		if (clientSecret != null) {
			// client secret post
			params.put(OidcUtil.OIDC_CLIENT_ID, client.getId());
			params.put(OidcUtil.CLIENT_SECRET, clientSecret);
		}
		return params;
	}

	public static String resolveClientSecret(OidcClient client) {
		var clientSecret = client.getClientSecret();
		if (clientSecret == null) {
			return null;
		}
		var noop = "{noop}";
		if (clientSecret.startsWith(noop)) {
			log.debug("Using noop clientId={} secret", client.getId());
			return clientSecret.substring(noop.length());
		}
		var file = "{file}";
		if (clientSecret.startsWith(file)) {
			var path = clientSecret.substring(file.length());
			log.debug("Using client={} secret from file={}", client.getId(), path);
			try {
				return Files.readString(Path.of(path));
			}
			catch (IOException ex) {
				throw new TechnicalException(
						String.format("Unable to read client=%s secret from file=%s", client.getId(), path), ex);
			}
		}
		log.error("Client={} secret has unknown type, using as-is", client.getId());
		return clientSecret;
	}

	public static String generateNonce() {
		return UUID.randomUUID().toString().replace("-", "");
	}
}
