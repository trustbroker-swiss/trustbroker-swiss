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

package swiss.trustbroker.util;

import swiss.trustbroker.common.config.KeystoreProperties;
import swiss.trustbroker.federation.xmlconfig.SignerKeystore;
import swiss.trustbroker.federation.xmlconfig.SignerStore;
import swiss.trustbroker.federation.xmlconfig.SignerTruststore;

/**
 * Utility function related to keys and certificates with dependencies to this subproject.
 *
 * @see swiss.trustbroker.common.saml.util.CredentialReader
 */
public class CertificateUtil {

	private CertificateUtil() {}

	public static KeystoreProperties toKeystoreProperties(SignerStore store) {
		var certPath = store.getResolvedCertPath() != null ? store.getResolvedCertPath() : store.getCertPath();
		var keyPath = store.getResolvedKeyPath() != null ? store.getResolvedKeyPath() : store.getKeyPath();
		return KeystoreProperties.builder()
								 .signerCert(certPath)
								 .password(store.getPassword())
								 .type(store.getCertType())
								 .keyEntryId(store.getAlias())
								 .signerKey(keyPath)
								 .build();
	}

	public static SignerKeystore toSignerKeystore(KeystoreProperties keystoreProperties) {
		return SignerKeystore.builder()
							 .certPath(keystoreProperties.getSignerCert())
							 .password(keystoreProperties.getPassword())
							 .certType(keystoreProperties.getType())
							 .alias(keystoreProperties.getKeyEntryId())
							 .keyPath(keystoreProperties.getSignerKey())
							 .build();
	}

	public static SignerTruststore toSignerTruststore(KeystoreProperties keystoreProperties) {
		return SignerTruststore.builder()
							   .certPath(keystoreProperties.getSignerCert())
							   .password(keystoreProperties.getPassword())
							   .certType(keystoreProperties.getType())
							   .alias(keystoreProperties.getKeyEntryId())
							   .keyPath(keystoreProperties.getSignerKey())
							   .build();
	}
}
