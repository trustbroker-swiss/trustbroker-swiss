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
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import swiss.trustbroker.config.dto.SamlProperties;
import swiss.trustbroker.federation.xmlconfig.Flow;
import swiss.trustbroker.saml.util.SamlStatusCode;

@Data
@Slf4j
public abstract class ResponseStatus implements Serializable {

    // Error handling: Script might abort the federation with a message to RP

    protected String statusCode; // usually urn:oasis:names:tc:SAML:2.0:status:Responder

    protected String statusNestedCode; // e.g. urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile

    protected String statusMessage; // e.g. SAML Federation not completed due to ....

    protected Flow flowPolicy;

    protected String accessCondition; // set by scripts, consumed by Access Request

    // used by scripts
    public void abort(String statusCode, String statusMessage, String statusNestedCode) {
        abort(statusCode, statusMessage, statusNestedCode, null);
    }

    // abort SAML exchange with a message to RP
    public void abort(String statusCode, Flow flowPolicy) {
        abort(statusCode, null, null, flowPolicy);
    }

    public void abort(String statusCode, String statusMessage, String statusNestedCode, Flow flowPolicy) {
        log.info("Abort request for statusCode={} statusMessage=\"{}\", statusNestedCode={}, flowPolicy={}",
                statusCode, statusMessage, statusNestedCode, flowPolicy);
        this.statusCode = statusCode;
        this.statusMessage = statusMessage;
        this.statusNestedCode = statusNestedCode;
        this.flowPolicy = flowPolicy;
    }

    @JsonIgnore // bean method
    public boolean isAborted() {
        return this.statusCode != null;
    }

	// used by scripts
	public void accessCondition(String accessCondition) {
		this.accessCondition = accessCondition;
	}

    public boolean showErrorPage() {
        return flowPolicy != null && flowPolicy.showErrorPage();
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

}
