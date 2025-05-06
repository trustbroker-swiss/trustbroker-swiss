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

package swiss.trustbroker.saml.dto;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;
import swiss.trustbroker.config.dto.SamlProperties;
import swiss.trustbroker.federation.xmlconfig.Flow;
import swiss.trustbroker.saml.util.SamlStatusCode;

/**
 * Base class for CP and RP side status codes.
 */
@Data
@Slf4j
@SuperBuilder(toBuilder = true)
@NoArgsConstructor
public abstract class ResponseStatus implements Serializable {

	/**
	 * Usually urn:oasis:names:tc:SAML:2.0:status:Responder
	 */
	protected String statusCode;

	/**
	 * E.g. urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile
	 */
	protected String statusNestedCode;

	/**
	 * E.g. SAML Federation not completed due to ....
	 */
	protected String statusMessage;

	/**
	 * Optional flow policy to control the abort flow.
	 */
	protected Flow flowPolicy;

	/**
	 * Set by scripts to toggle features, to be consumed by the respective implementations.
	 *
	 * @since 1.9.0
	 */
	@Builder.Default
	private Set<String> featureConditions = new HashSet<>();

	// Error handling: Script might abort the federation with a message to RP

	/**
	 * Abort a SAML exchange (script hook).
	 */
	public void abort(String statusCode, String statusMessage, String statusNestedCode) {
		abort(statusCode, statusMessage, statusNestedCode, null);
	}

	/**
	 * Abort a SAML exchange with a message to RP.
	 */
	public void abort(String statusCode, Flow flowPolicy) {
		abort(statusCode, null, null, flowPolicy);
	}

	/**
	 * Abort a SAML exchange with a message to RP.
	 */
	public void abort(String statusCode, String statusMessage, String statusNestedCode, Flow flowPolicy) {
		log.info("Abort request for statusCode={} statusMessage=\"{}\", statusNestedCode={}, flowPolicy={}",
				statusCode, statusMessage, statusNestedCode, flowPolicy);
		this.statusCode = statusCode;
		this.statusMessage = statusMessage;
		this.statusNestedCode = statusNestedCode;
		this.flowPolicy = flowPolicy;
	}

	/**
	 * Reset error page passed as flow policy to abort.
	 */
	public void resetErrorPageStatus() {
		if (showErrorPage()) {
			log.info("Clearing flow policy for statusCode={} statusMessage=\"{}\", statusNestedCode={}, flowPolicy={}",
					statusCode, statusMessage, statusNestedCode, flowPolicy);
			flowPolicy = Flow.builder()
							 .id(flowPolicy.getId())
							 .namespacePrefix(flowPolicy.getNamespacePrefix())
							 .build();
		}
	}

	public void copyAbortConditions(ResponseStatus responseStatus) {
		this.statusCode = responseStatus.getStatusCode();
		this.statusMessage = responseStatus.getStatusMessage();
		this.statusNestedCode = responseStatus.getStatusNestedCode();
		this.flowPolicy = responseStatus.getFlowPolicy();
	}

	@JsonIgnore // bean method
	public boolean isAborted() {
		return this.statusCode != null;
	}

	public boolean showErrorPage() {
		return isAborted() && flowPolicy != null && flowPolicy.showErrorPage();
	}

	public boolean doAppRedirect() {
		return flowPolicy != null && flowPolicy.doAppRedirect();
	}

	public String statusMessage() {
		return statusMessage(null);
	}

	public String statusMessage(SamlProperties samlProperties) {
		if (statusMessage != null) {
			return statusMessage;
		}
		return getSamlCode(samlProperties);
	}

	public String nestedStatusCode() {
		return nestedStatusCode(null);
	}

	public String nestedStatusCode(SamlProperties samlProperties) {
		if (statusNestedCode != null) {
			return statusNestedCode;
		}
		return getSamlCode(samlProperties);
	}

	private String getSamlCode(SamlProperties samlProperties) {
		if (flowPolicy == null) {
			return null;
		}
		return SamlStatusCode.addNamespace(samlProperties, flowPolicy.getId(), flowPolicy.getNamespacePrefix());
	}

	public String uiErrorCode() {
		return flowPolicy != null ? SamlStatusCode.toUiErrorCode(flowPolicy.getId()) : null;
	}

	public List<String> uiFlags() {
		return flowPolicy != null ? flowPolicy.uiFlags() : Collections.emptyList();
	}

	/**
	 * Script hook: Toggle features via conditions.
	 *
	 * @since 1.9.0
	 */
	public void featureConditions(Set<String> featureConditions) {
		log.debug("FeatureConditions={} set", featureConditions);
		if (featureConditions == null) {
			this.featureConditions = new HashSet<>();
		}
		else {
			// make sure it is modifiable
			this.featureConditions = new HashSet<>();
			this.featureConditions.addAll(featureConditions);
		}
	}

	/**
	 * Script hook: Add single feature condition.
	 * @return true if it was not present before
	 * @since 1.9.0
	 */
	public boolean addFeatureCondition(String featureCondition) {
		if ((featureCondition != null) && featureConditions.add(featureCondition)) {
			log.debug("FeatureCondition={} set", featureCondition);
			return true;
		}
		return false;
	}

	/**
	 * Script hook: Remove single feature condition.
	 * @return true if it was present
	 * @since 1.9.0
	 */
	public boolean removeFeatureCondition(String featureCondition) {
		if ((featureCondition != null) && featureConditions.remove(featureCondition)) {
			log.debug("FeatureCondition={} cleared", featureCondition);
			return true;
		}
		return false;
	}

	/**
	 * Script hook: Test single feature condition.
	 *
	 * @since 1.9.0
	 */
	public boolean hasFeatureCondition(String featureCondition) {
		if (featureCondition != null && featureConditions.contains(featureCondition)) {
			log.debug("FeatureCondition={} is present", featureCondition);
			return true;
		}
		return false;
	}

	/**
	 * Set condition for Access Request (script hook).
	 * <br/>
	 * Note that depending on the feature, only <code>RPRequest</code> or <code>CPResponse</code> may be checked.
	 *
	 * @deprecated replaced with <code>addFeatureCondition</code> / <code>setFeatureConditions</code>.
	 * @since 1.8.0
	 */
	@Deprecated(forRemoval = true, since = "1.9.0")
	public void accessCondition(String accessCondition) {
		addFeatureCondition(accessCondition);
	}
}
