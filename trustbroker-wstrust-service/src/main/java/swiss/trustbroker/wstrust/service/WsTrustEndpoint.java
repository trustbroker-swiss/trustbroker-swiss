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

package swiss.trustbroker.wstrust.service;

import javax.xml.namespace.QName;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.soap.wstrust.RequestSecurityToken;
import org.opensaml.soap.wstrust.RequestSecurityTokenResponseCollection;
import org.springframework.ws.server.endpoint.annotation.Endpoint;
import org.springframework.ws.server.endpoint.annotation.PayloadRoot;
import org.springframework.ws.server.endpoint.annotation.RequestPayload;
import org.springframework.ws.server.endpoint.annotation.ResponsePayload;
import org.springframework.ws.soap.SoapHeader;
import org.w3c.dom.Element;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SoapUtil;
import swiss.trustbroker.common.util.WSSConstants;
import swiss.trustbroker.wstrust.dto.SoapMessageHeader;

@Endpoint
@Slf4j
@AllArgsConstructor
public class WsTrustEndpoint {

	private static final String NAMESPACE_URI = WSSConstants.WST_NS_05_12;

	private final WsTrustService wsTrustService;

	@PayloadRoot(namespace = NAMESPACE_URI, localPart = RequestSecurityToken.ELEMENT_LOCAL_NAME)
	@ResponsePayload
	public Element processSecTokenRequest(@RequestPayload Element requestSecurityTokenType, SoapHeader soapHeader) {
		log.debug("Incoming RequestSecurityTokenType {}",
				requestSecurityTokenType == null ? null : requestSecurityTokenType.getNamespaceURI());
		SoapMessageHeader soapContext = null;
		try {

			// soapHeader above does not contain the required SAML security token, so we pass it from an interceptor via
			// ThreadLocal. Header contains the xml-sec element with the input assertion.
			soapContext = RequestLocalContextHolder.getRequestContext();

			// RST we shall process
			RequestSecurityToken requestSecurityToken = SoapUtil.unmarshallDomElement(requestSecurityTokenType);

			// service entry point
			RequestSecurityTokenResponseCollection response =
					wsTrustService.processSecurityTokenRequest(requestSecurityToken, soapContext.getAssertion());

			Marshaller marshaller = XMLObjectSupport.getMarshaller(new QName(WSSConstants.WST_NS_05_12,
					RequestSecurityTokenResponseCollection.ELEMENT_LOCAL_NAME));

			return marshaller.marshall(response);
		}
		catch (RequestDeniedException | TechnicalException e) {
			throw e;
		}
		catch (Exception e) {
			var samlString = OpenSamlUtil.samlObjectToString(soapContext == null ? null : soapContext.getAssertion());
			var rstString = OpenSamlUtil.domObjectToString(requestSecurityTokenType);
			throw new TechnicalException(String.format("Handling RST request failed with error '%s': RST: %s SAML assertion: %s",
					e.getMessage(), rstString, samlString), e);
		}
	}

}
