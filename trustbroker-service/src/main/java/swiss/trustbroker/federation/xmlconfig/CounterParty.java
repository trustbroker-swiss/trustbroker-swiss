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
import javax.annotation.Nonnull;

import jakarta.xml.bind.annotation.XmlTransient;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import swiss.trustbroker.common.saml.dto.SamlBinding;
import swiss.trustbroker.common.saml.dto.SignatureParameters;

/**
 * Abstraction for shared features of RP and CP.
 * <br/>
 * Design note: This base class could contain shared XML fields directly. But as it was retrofitted,
 * that would change the order of elements in the XML, breaking backward compatibility.
 *
 * @see RelyingParty
 * @see ClaimsParty
 * @since 1.8.0
 */
@Data
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
public abstract class CounterParty implements PathReference, Serializable {

	private transient String subPath;

	@Builder.Default
	private transient ValidationStatus validationStatus = new ValidationStatus();

	/**
	  * @return ID of the counterparty
	  */
	public abstract String getId();

	/**
	 * @return enabled flag from config or overridden due to validation errors
	 */
	public abstract FeatureEnum getEnabled();

	/**
	 * @param enabled override enabled flag
	 */
	public abstract void setEnabled(FeatureEnum enabled);

	/**
	 * @return type for logging etc. (RP/CP)
	 */
	@Nonnull
	public abstract String getShortType();

	/**
	 * @return Subject Name ID mappings for this party.
	 */
	public abstract SubjectNameMappings getSubjectNameMappings();

	/**
	 * @return SAML configuration
	 */
	public abstract Saml getSaml();

	/**
	 * @return Scripts
	 */
	public abstract Scripts getScripts();

	// XmlTransient not allowed on transient fields (the Javadoc does not say transient is considered XmlTransient):

	@XmlTransient
	@Override
	public String getSubPath() { return subPath; }

	@Override
	public void setSubPath(String subPath) { this.subPath = subPath; }

	@XmlTransient
	public ValidationStatus getValidationStatus() {
		return validationStatus;
	}

	@XmlTransient
	public boolean isValid() {
		return getEnabled() != FeatureEnum.INVALID;
	}

	// validation

	public void invalidate(Throwable ex) {
		setEnabled(FeatureEnum.INVALID);
		initializedValidationStatus().addException(ex);
	}

	public void invalidate(String error) {
		setEnabled(FeatureEnum.INVALID);
		initializedValidationStatus().addError(error);
	}

	public ValidationStatus initializedValidationStatus() {
		if (validationStatus == null) {
			validationStatus = new ValidationStatus();
		}
		return validationStatus;
	}

	public ProtocolEndpoints getSamlProtocolEndpoints() {
		var saml = getSaml();
		return saml != null ? saml.getProtocolEndpoints() : null;
	}

	public ArtifactBinding getSamlArtifactBinding() {
		var saml = getSaml();
		return saml != null ? saml.getArtifactBinding() : null;
	}

	public Encryption getEncryption() {
		var saml = getSaml();
		return saml != null ? saml.getEncryption() : null;
	}

	public Signature getSignature() {
		var saml = getSaml();
		return saml != null ? saml.getSignature() : null;
	}

	public SignatureParameters.SignatureParametersBuilder getSignatureParametersBuilder() {
		var saml = getSaml();
		return saml != null && saml.getSignature() != null ?
				saml.getSignature().getSignatureParametersBuilder() :
				SignatureParameters.builder();
	}

	public boolean isValidInboundBinding(SamlBinding samlBinding) {
		if (getSamlArtifactBinding() == null) {
			return true;
		}
		return getSamlArtifactBinding().validInboundBinding(samlBinding);
	}
}
