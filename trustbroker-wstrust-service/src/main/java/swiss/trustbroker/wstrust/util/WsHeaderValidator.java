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

package swiss.trustbroker.wstrust.util;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.soap.wsaddressing.Address;
import org.opensaml.soap.wstrust.WSTrustConstants;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.saml.util.AssertionValidator;
import swiss.trustbroker.wstrust.dto.SoapMessageHeader;

@Slf4j
public class WsHeaderValidator {

	private WsHeaderValidator() {
	}

	// Strict SOAP/SAML protocol checking from observation
	public static void validateHeaderElements(SoapMessageHeader requestHeader, String issuer) {
		log.debug("Validate WSTrust SOAP headers....");

		if (requestHeader == null) {
			throw new RequestDeniedException("SOAP request header missing");
		}
		var action = requestHeader.getAction();
		if (action == null || StringUtils.isBlank(action.getURI()) ||
				!action.getURI().equals(WSTrustConstants.WSA_ACTION_RST_ISSUE)) {
			throw new RequestDeniedException(String.format(
					"Action missing or invalid in SOAP header, action='%s'",
					action == null ? action : StringUtil.clean(action.getURI())));
		}

		var messageId = requestHeader.getMessageId();
		if (messageId == null || StringUtils.isBlank(messageId.getURI())) {
			throw new RequestDeniedException("MessageId missing in SOAP header");
		}

		var replyTo = requestHeader.getReplyTo();
		if (replyTo == null) {
			throw new RequestDeniedException("ReplyTo missing in SOAP header");
		}

		// see https://www.w3.org/TR/2006/REC-ws-addr-core-20060509/ fir the check below
		var address = replyTo.getAddress();
		if (address == null || StringUtils.isBlank(address.getURI()) || !address.getURI().equals(Address.ANONYMOUS)) {
			throw new RequestDeniedException(String.format(
					"Address missing or invalid in ReplyTo SOAP header, value='%s' accepted='%s'",
					address == null ? address : address.getURI(), Address.ANONYMOUS));
		}

		var to = requestHeader.getTo();
		if (to != null && to.getURI() != null && !toMatchWithIssuer(to.getURI(), issuer)) {
			log.warn("To missing or invalid in SOAP header, value='{}' accepted='{}'", to.getURI(), issuer);
		}
	}

	private static boolean toMatchWithIssuer(String to, String issuer) {
		var firstDelimiter = "://";
		var lastDelimiter = "/";

		var toHost = "";
		var issuerHost = "";

		if (to.contains(firstDelimiter)) {
			toHost = to.substring(to.indexOf(firstDelimiter) + firstDelimiter.length());
		}
		if (issuer.contains(firstDelimiter)) {
			issuerHost = issuer.substring(issuer.indexOf(firstDelimiter) + firstDelimiter.length());
		}

		if (toHost.contains(lastDelimiter)) {
			toHost = toHost.substring(0, toHost.indexOf(lastDelimiter));
		}

		if (issuerHost.contains(lastDelimiter)) {
			issuerHost = issuerHost.substring(0, issuerHost.indexOf(lastDelimiter));
		}

		return toHost.equals(issuerHost);
	}

	public static void validateAssertion(Assertion assertion, TrustBrokerProperties properties) {
		AssertionValidator.validateRstAssertion(assertion, properties, null);
	}

}
