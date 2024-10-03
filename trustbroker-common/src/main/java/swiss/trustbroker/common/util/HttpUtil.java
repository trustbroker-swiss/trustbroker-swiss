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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import javax.net.ssl.SSLContext;

import org.apache.commons.lang3.StringUtils;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import swiss.trustbroker.common.config.KeystoreProperties;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.CredentialUtil;

public class HttpUtil {

	private HttpUtil() {
	}

	public static HttpClient createHttpClient(URI applicationUrl, KeystoreProperties truststoreParameters) {
		return createHttpClient(applicationUrl, truststoreParameters, null, null);
	}

	public static HttpClient createHttpClient(URI applicationUrl,
			KeystoreProperties truststoreParameters, KeystoreProperties keystoreParameters, String keystoreBasePath) {
		var sslContext = createSSLContext(applicationUrl, truststoreParameters, keystoreParameters, keystoreBasePath);
		return HttpClient.newBuilder()
				.sslContext(sslContext)
				.version(HttpClient.Version.HTTP_2)
				.build();
	}

	public static CloseableHttpClient createApacheHttpClient(URI applicationUrl,
			KeystoreProperties truststoreParameters, KeystoreProperties keystoreParameters,
			String keystoreBasePath, String proxyUrl) {
		var sslContext = createSSLContext(applicationUrl, truststoreParameters, keystoreParameters, keystoreBasePath);
		var httpProxy = createHttpProxy(proxyUrl);
		final SSLConnectionSocketFactory sslSocketFactory = SSLConnectionSocketFactoryBuilder.create()
																							 .setSslContext(sslContext)
																							 .build();
		final HttpClientConnectionManager cm = PoolingHttpClientConnectionManagerBuilder.create()
																						.setSSLSocketFactory(sslSocketFactory)
																						.build();
		return HttpClients.custom()
						  .setConnectionManager(cm)
						  .setProxy(httpProxy)
						  .build();
	}

	private static HttpHost createHttpProxy(String proxyUrl) {
		if (StringUtils.isEmpty(proxyUrl)) {
			return null;
		}
		try {
			var proxyUri = new URI(proxyUrl);
			return new HttpHost(proxyUri.getScheme(), proxyUri.getHost(), proxyUri.getPort());
		}
		catch (URISyntaxException ex) {
			throw new TechnicalException(String.format("Could not parse proxyUrl=%s message=%s", proxyUrl, ex.getMessage()), ex);
		}
	}

	private static SSLContext createSSLContext(URI applicationUrl, KeystoreProperties truststoreParameters,
			KeystoreProperties keystoreParameters, String keystoreBasePath) {
		try {
			var builder = SSLContextBuilder.create();
			if (applicationUrl.getScheme()
							  .equals("https")) {
				if (truststoreParameters != null && StringUtils.isNotEmpty(truststoreParameters.getSignerCert())) {
					var password = CredentialUtil.processPassword(truststoreParameters.getPassword());
					builder.loadTrustMaterial(
							absoluteFile(keystoreBasePath, truststoreParameters.getSignerCert()),
							CredentialUtil.passwordToCharArray(password));
				}
				if (keystoreParameters != null && StringUtils.isNotEmpty(keystoreParameters.getSignerCert())) {
					var password = CredentialUtil.processPassword(keystoreParameters.getPassword());
					builder.loadKeyMaterial(
							absoluteFile(keystoreBasePath, keystoreParameters.getSignerCert()),
							CredentialUtil.passwordToCharArray(password),
							CredentialUtil.passwordToCharArray(password));
				}
			}
			return builder.build();
		}
		catch (FileNotFoundException ex) {
			throw new TechnicalException(String.format("truststoreParameters=%s keystoreParameters=%s not found for SSLContext",
					truststoreParameters, keystoreParameters), ex);
		}
		catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException |
			   UnrecoverableKeyException | KeyManagementException ex) {
			throw new TechnicalException(String.
					format("Building SSLContext failed for truststoreParameters=%s keystoreParameters=%s ",
							truststoreParameters, keystoreParameters), ex);
		}
	}

	// configs may only contain the path relative to the keystore directory
	private static File absoluteFile(String keystoreBasePath, String keystorePath) {
		var result = new File(keystorePath);
		if (result.isAbsolute()) {
			return result;
		}
		return new File(keystoreBasePath, keystorePath);
	}

	public static int getDefaultPort(URI uri) {
		if (uri == null) {
			return -1;
		}
		return switch (uri.getScheme()) {
			case "http" -> 80;
			case "htps" -> 443;
			default -> -1;
		};
	}

}
