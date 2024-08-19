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

package swiss.trustbroker.audit.dto;

import java.sql.Timestamp;
import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import org.opensaml.core.xml.XMLObject;

/**
 * Represents the data that we can base reports on.
 */
@Data
@Builder
public class AuditDto {

	public enum AttributeSource {
		SAML_RESPONSE("r"), // SAML response
		IDP_RESPONSE("c"), // CP response filtered
		DROPPED_RESPONSE("x"), // CP response dropped
		OIDC_RESPONSE(""); // no tagging

		private final String shortName;

		private AttributeSource(String shortName) {
			this.shortName = shortName;
		}

		public String getShortName() {
			return shortName;
		}
	}

	@Data
	@Builder
	@AllArgsConstructor(staticName = "of")
	public static class ResponseAttributeValue {

		private Object value;

		private String postfix;

		private AttributeSource source;

		private long count;
	}

	// RAW data and message identification

	@CustomLogging
	private EventType eventType; // maps to 'event'

	private String status; // response only

	private String statusMessage; // response only

	private String nestedStatus; // response only

	// SAML user attributes

	private String principal; // from response Subject NameID usually

	private String cpNameId; // incoming CP side principal

	// HTTP request attributes

	private String clientIP; // X-Forwarded-For, not reliable and may be issues in K8S

	private String clientType; // HTTP User-Agent (as in most access logs)

	private String clientNetwork; // Client_Network HTTP header

	private String entryId; // HTTP Host header

	private String deviceId; // XTB device ID from client

	private String deviceIdAccepted; // XTB device ID in session

	private String transferId; // unused as we are not behind reverse proxy and LB does not send tracr ID

	private String url; // accessed service endpoint (drop when we start putting REST data into the URL may be)

	private String referrer; // HTTP Referer header for debugging and config addressing

	private String rpReferrer; // useful for network and RP analysis (typo by HTTP standard using referer fixed)

	private String applicationName; // AuthnRequest.ProviderName to handle RP-ID ambiguities

	private String oidcClientId; // allow correlation of a SAML flow with its OIDC initiator

	// Authentication process attributes

	private String clientName; // tenant (primary key clientExtId is handled via attribute definitions)

	private String profileExtId; // user profile selected

	private String billingId; // bookkeeping account for billing

	private String authLevel; // response only

	private String ctxClasses; // response only, better than authLevel because that's just config mostly

	private String issuer; // from message (authnrequest or response) in the end ourselves

	private String rpIssuer; // from state (authnrequest)

	private String cpIssuer; // from state (response)

	private String destination; // authnrequest only

	private String assertionConsumerUrl; // authnrequest only

	private Long loginDurationSecs; // seconds between login initiation and completion

	// correlation attributes

	private String conversationId; // authnrequest.ID and response.inResponseTO

	private String sessId; // SSO/SLO future use

	private String ssoSessionId; // external session mapped to http://trustbroker.swiss/claims/ssoSessionId

	private String ssoGroupName; // name of SSO group of SSO session

	private String ssoQoa; // QOA of the SSO session

	private Integer ssoParticipantCount; // number of participants  in SSO (Integer to allow null if no SSO)

	private Timestamp ssoEstablishedTime; // time when the SSO session was established

	// access request attributes

	private String arResponseId; // ID of the SAML response towards AR

	private String arState; // state of the AR

	private String arMode; // mode of the AR

	private String arReturnUrl; // return URL of the triggering application

	private Long arDurationSecs; // seconds between sending of AR and completion (includes user interaction for interactive case)

	private Timestamp expirationTime; // time when the session will expire

	// SAML Response attributes (contains many IdP related user attributes, see AttributeName.java)
	// Put this one at the end as Splunk stops indexing after 8k

	private Map<String, ResponseAttributeValue> responseAttributes; // FQ name in DEBUG level

	@CustomLogging
	private XMLObject samlMessage; // TRACE level

}
