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
 * SAML protocol endpoints.
 *
 * @see <a href="http://saml.xml.org/saml-specifications">SAML Specifications</a>
 */
@XmlRootElement(name = "ProtocolEndpoints")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProtocolEndpoints implements Serializable {

	/**
	 * SAML metadata URL.
	 */
	@XmlElement(name = "MetadataUrl")
	private String metadataUrl;

	/**
	 * SAML Artifact Resolution Protocol URL.
	 */
	@XmlElement(name = "ArtifactResolutionUrl")
	private String artifactResolutionUrl;

	/**
	 * SAML Artifact Resolution Protocol index.
	 */
	@XmlElement(name = "ArtifactResolutionIndex")
	private int artifactResolutionIndex;

	/**
	 * 	Proxy URL overrides global default.
	 * 	<br/>
	 *  Set to empty string to override without proxy.
	 */
	@XmlElement(name = "ArtifactResolutionProxyUrl")
	private String artifactResolutionProxyUrl;

}
