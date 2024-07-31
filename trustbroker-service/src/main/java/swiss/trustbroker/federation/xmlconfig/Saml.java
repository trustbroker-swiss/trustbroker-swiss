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

package swiss.trustbroker.federation.xmlconfig;

import java.io.Serializable;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * SAML configuration for CP/RP.
 */
@XmlRootElement(name = "Saml")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Saml implements Serializable {

	/**
	 * SAML protocol endpoint configuration.
	 */
	@XmlElement(name = "ProtocolEndpoints")
	private ProtocolEndpoints protocolEndpoints;

	/**
	 * SAML Artifact Binding configuration
	 */
	@XmlElement(name = "ArtifactBinding")
	private ArtifactBinding artifactBinding;

	/**
	 * SAML encryption configuration.
	 */
	@XmlElement(name = "Encryption")
	private Encryption encryption;

	/**
	 * SAML signature configuration.
	 */
	@XmlElement(name = "Signature")
	private Signature signature;

	public Signature initializedSignature() {
		if (signature == null) {
			signature = new Signature();
		}
		return signature;
	}

	public Encryption initializedEncryption() {
		if (encryption == null) {
			encryption = new Encryption();
		}
		return encryption;
	}

	public ArtifactBinding initializedArtifactBinding() {
		if (artifactBinding == null) {
			artifactBinding = new ArtifactBinding();
		}
		return artifactBinding;
	}

	public ProtocolEndpoints initializedProtocolEndpoints() {
		if (protocolEndpoints == null) {
			protocolEndpoints = new ProtocolEndpoints();
		}
		return protocolEndpoints;
	}

}
