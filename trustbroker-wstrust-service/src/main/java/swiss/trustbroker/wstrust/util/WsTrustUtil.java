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

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import javax.xml.namespace.QName;

import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.soap.wsfed.Address;
import org.opensaml.soap.wsfed.EndPointReference;
import org.opensaml.soap.wspolicy.AppliesTo;
import org.opensaml.soap.wssecurity.Created;
import org.opensaml.soap.wssecurity.Expires;
import org.opensaml.soap.wssecurity.KeyIdentifier;
import org.opensaml.soap.wssecurity.SecurityTokenReference;
import org.opensaml.soap.wssecurity.WSSecurityConstants;
import org.opensaml.soap.wstrust.KeyType;
import org.opensaml.soap.wstrust.Lifetime;
import org.opensaml.soap.wstrust.RequestType;
import org.opensaml.soap.wstrust.RequestedAttachedReference;
import org.opensaml.soap.wstrust.RequestedUnattachedReference;
import org.opensaml.soap.wstrust.TokenType;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.util.WSSConstants;

public class WsTrustUtil {

	private WsTrustUtil() {}

	public static Lifetime createLifeTime() {
		Lifetime lifetime = (Lifetime) XMLObjectSupport.buildXMLObject(Lifetime.ELEMENT_NAME);
		lifetime.setCreated(createCreated());
		lifetime.setExpires(createExpires());
		return lifetime;
	}

	public static Expires createExpires() {
		Expires expires = (Expires) XMLObjectSupport.buildXMLObject(Expires.ELEMENT_NAME);
		Instant dateTime = Instant.now();
		Instant expiresDate = dateTime.plus(8,  ChronoUnit.HOURS);
		expires.setDateTime(expiresDate);
		return expires;
	}

	public static Created createCreated() {
		Created created = (Created) XMLObjectSupport.buildXMLObject(Created.ELEMENT_NAME);
		created.setDateTime(Instant.now());
		return created;
	}

	public static AppliesTo createResponseAppliesTo(String subjectCondition) {
		AppliesTo appliesTo = (AppliesTo) XMLObjectSupport.buildXMLObject(AppliesTo.ELEMENT_NAME);
		appliesTo.getUnknownXMLObjects().add(createResponseEndpointReference(subjectCondition));
		return appliesTo;
	}

	public static EndPointReference createResponseEndpointReference(String subjectCondition) {
		EndPointReference endPointReference = OpenSamlUtil.buildSamlObject(EndPointReference.class);
		endPointReference.setAddress(createEndpointRefAddress(subjectCondition));
		return endPointReference;
	}

	public static Address createEndpointRefAddress(String subjectCondition) {
		Address address = OpenSamlUtil.buildSamlObject(Address.class);
		address.setValue(subjectCondition);

		return address;
	}

	public static KeyType createKeyType(String keyTypeValue) {
		KeyType keyType = (KeyType) XMLObjectSupport.buildXMLObject(KeyType.ELEMENT_NAME);
		keyType.setURI(keyTypeValue);
		return keyType;
	}

	public static TokenType createTokenType() {
		TokenType tokenType = (TokenType) XMLObjectSupport.buildXMLObject(TokenType.ELEMENT_NAME);
		tokenType.setURI("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
		return tokenType;
	}

	public static RequestType createRequestType(String typeValue) {
		RequestType requestType = (RequestType) XMLObjectSupport.buildXMLObject(RequestType.ELEMENT_NAME);
		requestType.setURI(typeValue);

		return requestType;
	}

	public static RequestedUnattachedReference createRequestUnattachedRef(String assertionId) {
		RequestedUnattachedReference requestedUnattachedReference =
				(RequestedUnattachedReference) XMLObjectSupport.buildXMLObject(RequestedUnattachedReference.ELEMENT_NAME);
		requestedUnattachedReference.setSecurityTokenReference(createSecurityTokenReference(assertionId));

		return requestedUnattachedReference;
	}

	public static RequestedAttachedReference createRequestedAttachedRef(String assertionId) {
		RequestedAttachedReference requestedAttachedReference =
				(RequestedAttachedReference) XMLObjectSupport.buildXMLObject(RequestedAttachedReference.ELEMENT_NAME);
		requestedAttachedReference.setSecurityTokenReference(createSecurityTokenReference(assertionId));

		return requestedAttachedReference;
	}

	public static SecurityTokenReference createSecurityTokenReference(String assertionId) {
		SecurityTokenReference securityTokenReference =
				(SecurityTokenReference) XMLObjectSupport.buildXMLObject(SecurityTokenReference.ELEMENT_NAME);
		securityTokenReference.getUnknownAttributes().put(createTokenTypeAttribute(), createTokenTypeAttributeValue());
		securityTokenReference.getUnknownXMLObjects().add(createKeyIdentifier(assertionId));
		return securityTokenReference;
	}

	public static KeyIdentifier createKeyIdentifier(String assertionId) {
		KeyIdentifier keyIdentifier = (KeyIdentifier) XMLObjectSupport.buildXMLObject(KeyIdentifier.ELEMENT_NAME);
		keyIdentifier.setValue(assertionId);
		keyIdentifier.setValueType(WSSConstants.WSS_SAML2_KI_VALUE_TYPE);
		return keyIdentifier;
	}

	public static QName createTokenTypeAttribute() {
		return new QName(WSSecurityConstants.WSSE11_NS, TokenType.ELEMENT_LOCAL_NAME, "b");
	}

	public static QName createTokenTypeAttributeValue() {
		return new QName(WSSecurityConstants.WSSE11_NS, WSSConstants.WSS_SAML2_TOKEN_TYPE);
	}
}
