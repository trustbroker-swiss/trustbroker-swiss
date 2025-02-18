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

import java.time.Instant;
import java.util.List;

import lombok.Builder;
import lombok.Data;
import org.opensaml.security.credential.Credential;
import swiss.trustbroker.common.config.RegexNameValue;

@Data
@Builder
public class ResponseParameters {

	// input parameters RP side

	private String conversationId; // override message ID

	private String rpIssuerId;

	private String rpReferer;

	private String rpAuthnRequestId;

	private Credential credential;

	// federation processing

	private String issuerId;

	private String nameId;

	private String nameIdFormat;

	private String nameIdQualifier;

	private String federationServiceIssuerId;

	private String recipientId;

	private boolean setOriginalIssuerIfEmpty;

	private List<String> dropDuplicatedAttributeFromOriginalIssuer;

	private List<RegexNameValue> homeNameIssuerMapping;

	private String rpClientName;

	private String cpAttrOriginIssuer;

	// validity policies

	private long subjectValiditySeconds;

	private long audienceValiditySeconds;

	private Instant issuerInstant;

	private Instant authnStatementInstant;

	@Builder.Default
	private boolean setSessionIndex = true;

	// presentation polices

	private String skinnyAssertionStyle;

	public boolean isAccessRequest() {
		return homeNameIssuerMapping != null && !homeNameIssuerMapping.isEmpty();
	}
}
