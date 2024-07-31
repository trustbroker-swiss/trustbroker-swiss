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

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.xml.namespace.QName;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.soap.wstrust.KeyType;
import org.opensaml.soap.wstrust.RequestSecurityToken;
import org.opensaml.soap.wstrust.RequestSecurityTokenResponse;
import org.opensaml.soap.wstrust.RequestSecurityTokenResponseCollection;
import org.opensaml.soap.wstrust.RequestType;
import org.opensaml.soap.wstrust.RequestedSecurityToken;
import org.opensaml.soap.wstrust.TokenType;
import org.opensaml.soap.wstrust.WSTrustConstants;
import org.springframework.stereotype.Service;
import org.w3c.dom.Element;
import swiss.trustbroker.api.idm.service.IdmService;
import swiss.trustbroker.audit.service.AuditService;
import swiss.trustbroker.audit.service.OutboundAuditMapper;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.saml.util.SamlTracer;
import swiss.trustbroker.common.saml.util.SamlUtil;
import swiss.trustbroker.common.util.WSSConstants;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.ConstAttributes;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.homerealmdiscovery.util.DefaultIdmStatusPolicyCallback;
import swiss.trustbroker.homerealmdiscovery.util.DefinitionUtil;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.saml.service.RelyingPartyService;
import swiss.trustbroker.saml.util.AssertionValidator;
import swiss.trustbroker.saml.util.ResponseFactory;
import swiss.trustbroker.script.service.ScriptService;
import swiss.trustbroker.wstrust.util.WsTrustUtil;

@Service
@AllArgsConstructor
@Slf4j
public class WsTrustService {

	private final TrustBrokerProperties trustBrokerProperties;

	private final List<IdmService> idmServices;

	private final RelyingPartySetupService relyingPartySetupService;

	private final ScriptService scriptService;

	private final RelyingPartyService relyingPartyService;

	private final AuditService auditService;

	public RequestSecurityTokenResponseCollection createResponse(Map<Definition, List<String>> idmResponse,
			List<Attribute> cpAttributes, Map<Definition, List<String>> properties, Assertion requestHeaderAssertion,
			String addressFromRequest) {

		RequestSecurityTokenResponseCollection responseCollection = (RequestSecurityTokenResponseCollection) XMLObjectSupport
				.buildXMLObject(RequestSecurityTokenResponseCollection.ELEMENT_NAME);

		responseCollection.getRequestSecurityTokenResponses().add(createSecurityTokenResponse(idmResponse, cpAttributes,
				properties, requestHeaderAssertion, addressFromRequest));

		return responseCollection;
	}

	private RequestSecurityTokenResponse createSecurityTokenResponse(Map<Definition, List<String>> idmResponse,
			List<Attribute> cpAttributes, Map<Definition, List<String>> properties, Assertion requestHeaderAssertion, String addressFromRequest) {
		var requestSecurityTokenResponse =
				(RequestSecurityTokenResponse) XMLObjectSupport.buildXMLObject(RequestSecurityTokenResponse.ELEMENT_NAME);

		// Current implementation SAML Token Lifetime 8 Std.
		var lifetime = WsTrustUtil.createLifeTime();
		requestSecurityTokenResponse.getUnknownXMLObjects().add(lifetime);

		var appliesTo = WsTrustUtil.createResponseAppliesTo(addressFromRequest);
		requestSecurityTokenResponse.getUnknownXMLObjects().add(appliesTo);

		var assertionId = OpenSamlUtil.generateSecureRandomId();

		var requestedSecurityToken = createRequestedSecurityToken(idmResponse, cpAttributes, properties,
				assertionId, requestHeaderAssertion, addressFromRequest);
		requestSecurityTokenResponse.getUnknownXMLObjects().add(requestedSecurityToken);

		var requestedAttachedReference = WsTrustUtil.createRequestedAttachedRef(assertionId);
		requestSecurityTokenResponse.getUnknownXMLObjects().add(requestedAttachedReference);

		var requestedUnattachedReference = WsTrustUtil.createRequestUnattachedRef(assertionId);
		requestSecurityTokenResponse.getUnknownXMLObjects().add(requestedUnattachedReference);

		var tokenType = WsTrustUtil.createTokenType();
		requestSecurityTokenResponse.getUnknownXMLObjects().add(tokenType);

		var requestType = WsTrustUtil.createRequestType(RequestType.ISSUE);
		requestSecurityTokenResponse.getUnknownXMLObjects().add(requestType);

		var keyType = WsTrustUtil.createKeyType(KeyType.BEARER);
		requestSecurityTokenResponse.getUnknownXMLObjects().add(keyType);

		return requestSecurityTokenResponse;
	}

	private RequestedSecurityToken createRequestedSecurityToken(Map<Definition, List<String>> idmResponse,
			List<Attribute> cpAttributes, Map<Definition, List<String>> properties, String assertionId,
			Assertion requestHeaderAssertion, String addressFromRequest) {
		var requestedSecurityToken =
				(RequestedSecurityToken) XMLObjectSupport.buildXMLObject(RequestedSecurityToken.ELEMENT_NAME);
		var assertion = createAssertion(idmResponse, cpAttributes, properties, assertionId, requestHeaderAssertion,
				addressFromRequest);
		requestedSecurityToken.setUnknownXMLObject(assertion);

		// trace
		SamlTracer.logSamlObject("<<<<< Outgoing RSTR", assertion);

		// audit
		auditRstResponseToClient(assertion, addressFromRequest);

		return requestedSecurityToken;
	}

	private Assertion createAssertion(Map<Definition, List<String>> idmResponse, List<Attribute> cpAttributes,
			Map<Definition, List<String>> properties, String assertionId, Assertion requestHeaderAssertion, String addressFromRequest) {
		var assertion = OpenSamlUtil.buildAssertionObject(trustBrokerProperties.getSkinnyAssertionNamespaces());

		assertion.setID(assertionId);
		assertion.setIssueInstant(Instant.now());
		assertion.setVersion(SAMLVersion.VERSION_20);

		var issuer = trustBrokerProperties.getIssuer();
		assertion.setIssuer(SamlFactory.createIssuer(issuer));

		var rp = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(addressFromRequest, null);
		var signature = SamlFactory.prepareSignableObject(
				assertion,
				rp.getSignatureParametersBuilder().build());

		var requestNameId = requestHeaderAssertion.getSubject().getNameID();
		var nameIdFormat = requestNameId.getFormat();
		var nameId = SamlFactory.createNameId(requestNameId.getValue(), nameIdFormat,
				requestNameId.getNameQualifier());

		// Allow Condition.notOnOrAfter to be customizable per calling RP
		var tokenLifetime = relyingPartySetupService.getTokenLifetime(addressFromRequest, null);
		assertion.setSubject(SamlFactory.createSubject(nameId, null, null, tokenLifetime));
		assertion.setConditions(SamlFactory.createConditions(addressFromRequest, tokenLifetime));

		ConstAttributes constantAttributes = relyingPartySetupService.getConstantAttributes(addressFromRequest, null);

		var rpClientName = relyingPartySetupService.getRpClientName(addressFromRequest, null);
		assertion.getAttributeStatements()
				.add(createAttributeStatement(idmResponse, constantAttributes, cpAttributes, properties, rpClientName));
		var authnContextClassRef =
				requestHeaderAssertion.getAuthnStatements().get(0).getAuthnContext().getAuthnContextClassRef().getURI();
		List<String> requestAuthnContextClassRefs = List.of(authnContextClassRef);
		assertion.getAuthnStatements().addAll(SamlFactory.createAuthnState(requestAuthnContextClassRefs, null, Instant.now()));

		SamlUtil.signSamlObject(assertion, signature, trustBrokerProperties.getSkinnyAssertionNamespaces());

		return assertion;
	}

	public static AttributeStatement createAttributeStatement(Map<Definition, List<String>> userDetailsFromIdm,
			ConstAttributes constAttr, List<Attribute> cpAttributes, Map<Definition, List<String>> properties, String clientName) {
		Collection<Attribute> attributes = createAttributes(userDetailsFromIdm, constAttr, properties, clientName);
		if (cpAttributes != null && !cpAttributes.isEmpty()) {
			attributes.addAll(cpAttributes);
		}
		List<Attribute> filteredAttributes = SamlFactory.filterDuplicatedAttributes(attributes);

		return SamlFactory.createAttributeStatement(filteredAttributes);
	}

	static Collection<Attribute> createAttributes(Map<Definition, List<String>> userDetailsFromIdm,
			ConstAttributes constAttr, Map<Definition, List<String>> properties, String clientName) {
		List<Attribute> attributeList = new ArrayList<>();

		List<Attribute> idmAttributes = ResponseFactory.createUserDetailsAttributes(userDetailsFromIdm, clientName);
		if (!idmAttributes.isEmpty()) {
			attributeList.addAll(idmAttributes);
		}

		List<Attribute> constAttributes = ResponseFactory.createConstAttributes(constAttr, clientName);
		if (!constAttributes.isEmpty()) {
			attributeList.addAll(constAttributes);
		}

		List<Attribute> userProperties = ResponseFactory.createUserDetailsAttributes(properties, clientName);
		if (!userProperties.isEmpty()) {
			attributeList.addAll(userProperties);
		}

		return attributeList;
	}

	public RequestSecurityTokenResponseCollection processSecurityTokenRequest(
			RequestSecurityToken requestSecurityToken, Assertion headerAssertion) {

		// Validate the assertion on XTB level only per default. The wss4j layer doing the same is deprecated and can be dropped.
		if (trustBrokerProperties.getSecurity().isValidateSecurityTokenRequestAssertion()) {
			AssertionValidator.validateRstAssertion(headerAssertion, trustBrokerProperties, null);
		}
		else {
			log.warn("trustbroker.config.security.validateSecurityTokenRequestAssertion=false, XTB validation disabled!!!");
		}

		List<AttributeStatement> requestAttributeStatements = headerAssertion.getAttributeStatements();

		// trace
		SamlTracer.logSamlObject(">>>>> Incoming RST", headerAssertion);

		// accept request
		processSecurityToken(requestSecurityToken, headerAssertion.getID());
		String addressFromRequest = getAddressFromRequest(requestSecurityToken);
		log.debug("Incoming RST accepted -> send RSTR");

		// audit
		auditRstRequestFromClient(headerAssertion, addressFromRequest);

		// processing
		var cpResponse = createCpResponseDto(headerAssertion, addressFromRequest);

		scriptService.processCpBeforeIdm(cpResponse, null, cpResponse.getIssuer(), "");

		// Filter by CP config AttributeSelection
		List<Definition> cpAttributeDefinitions = relyingPartySetupService.getCpAttributeDefinitions(cpResponse.getIssuer(),
				"");
		if (!cpAttributeDefinitions.isEmpty()) {
			ResponseFactory.filterCpAttributes(cpResponse, cpAttributeDefinitions);
		}

		scriptService.processRpBeforeIdm(cpResponse, null, addressFromRequest, "");

		Map<Definition, List<String>> queryResponse = getResponseQueryElements(headerAssertion, addressFromRequest, cpResponse);
		cpResponse.getUserDetails().putAll(queryResponse);

		// Filter by RP config AttributeSelection
		List<Definition> rpConfigAttributesDefinition =
				relyingPartySetupService.getRpAttributesDefinitions(addressFromRequest, null);
		filterCpAttributesByRpConfig(rpConfigAttributesDefinition, cpResponse);

		relyingPartyService.setProperties(cpResponse);

		scriptService.processRpAfterIdm(cpResponse, null, addressFromRequest, "");

		relyingPartyService.filterPropertiesSelection(cpResponse, addressFromRequest, "");

		List<Attribute> cpAttributes = createCpAttributes(cpResponse.getAttributes(), rpConfigAttributesDefinition,
				requestAttributeStatements, headerAssertion);

		return createResponse(cpResponse.getUserDetails(), cpAttributes, cpResponse.getProperties(), headerAssertion,
				addressFromRequest);
	}

	private static void filterCpAttributesByRpConfig(List<Definition> rpConfigAttributesDefinition, CpResponse cpResponse) {
		if (!rpConfigAttributesDefinition.isEmpty()) {
			ResponseFactory.filterCpAttributes(cpResponse, rpConfigAttributesDefinition);
		}
	}

	void processSecurityToken(RequestSecurityToken requestSecurityToken, String assertionId) {
		if (requestSecurityToken == null) {
			throw new RequestDeniedException("Missing WS-Trust RequestSecurityToken in request");
		}
		var childrenObjects = requestSecurityToken.getUnknownXMLObjects();

		var keyTypeQname = new QName(WSTrustConstants.WST_NS, KeyType.ELEMENT_LOCAL_NAME);
		var keyType = (KeyType) findChildObjectByQname(childrenObjects, keyTypeQname);
		isRequired(keyType, false, requestSecurityToken);

		if (keyType == null) {
			throw new RequestDeniedException(String.format(
					"Missing KeyType in RSTR with assertionID='%s'", assertionId));
		}
		if (!KeyType.BEARER.equals(keyType.getURI())) {
			throw new RequestDeniedException(String.format(
					"Wrong KeyType in RSTR with assertionID='%s' keyType='%s' expectedKeyType='%s'",
					assertionId, keyType.getURI(), KeyType.BEARER));
		}

		var requestTypeQname = new QName(WSTrustConstants.WST_NS, RequestType.ELEMENT_LOCAL_NAME);
		var requestType = (RequestType) findChildObjectByQname(childrenObjects, requestTypeQname);
		if (requestType == null) {
			throw new RequestDeniedException(String.format(
					"Missing RequestType in RSTR with assertionID='%s'", assertionId));
		}
		if (!RequestType.ISSUE.equals(requestType.getURI())) {
			throw new RequestDeniedException(String.format(
					"Wrong RequestType in RSTR with assertionID='%s' requestType='%s' but expectedRequestType=%s",
					assertionId, requestType.getURI(), RequestType.ISSUE));
		}

		var tokenTypeQname = new QName(WSTrustConstants.WST_NS, TokenType.ELEMENT_LOCAL_NAME);
		var tokenType = (TokenType) findChildObjectByQname(childrenObjects, tokenTypeQname);
		isRequired(tokenType, false, requestSecurityToken);

		if (tokenType == null) {
			throw new RequestDeniedException(String.format(
					"Missing TokenType in RSTR with AssertionID='%s'", assertionId));
		}
		if (!WSSConstants.WSS_SAML2_TOKEN_TYPE.equals(tokenType.getURI())) {
			throw new RequestDeniedException(String.format(
					"Wrong TokenType in RSTR with assertionID='%s' tokenType='%s' but expectedTokenType='%s'",
					assertionId, tokenType.getURI(), WSSConstants.WSS_SAML2_TOKEN_TYPE));
		}
	}

	private static XMLObject findChildObjectByQname(List<XMLObject> childrenObjects, QName qName) {
		for (XMLObject xmlObject : childrenObjects) {
			if (xmlObject.getElementQName().equals(qName)) {
				return xmlObject;
			}
		}
		return null;
	}

	private static void isRequired(XMLObject elementValue, boolean required, XMLObject requestSecurityToken) {
		if (elementValue == null && required) {
			throw new RequestDeniedException(String.format(
					"One of the security elements is missing from message: %s",
					OpenSamlUtil.samlObjectToString(requestSecurityToken)));
		}
	}

	@SuppressWarnings("java:S2629")
	private static List<Attribute> createCpAttributes(
			Map<Definition, List<String>> cpAttributes, List<Definition> rpConfigAttributesDefinition,
			List<AttributeStatement> requestAttributeStatements, Assertion assertion) {

		List<Attribute> attributes = new ArrayList<>();
		// attribute statements
		// NOTE: Some send no attribute statements, so we make this debug
		if (cpAttributes == null || cpAttributes.isEmpty()) {
			log.debug("There are no CP attributes : {}", OpenSamlUtil.samlObjectToString(assertion));
		}
		else {
			for (Definition definition : rpConfigAttributesDefinition) {
				var name = definition.getNamespaceUri();
				var values = DefinitionUtil.findListByNameOrNamespace(name, cpAttributes);
				if (!values.isEmpty()) {
					attributes.add(SamlFactory.createAttribute(definition.getNamespaceUri(), values,
							getOriginalIssuerFromInput(requestAttributeStatements, definition)));
				}
			}
		}

		return new ArrayList<>(attributes);
	}

	// Request can have attributes with different OriginalIssuer
	private static String getOriginalIssuerFromInput(List<AttributeStatement> requestAttributeStatements, Definition definition) {
		if (requestAttributeStatements != null && !requestAttributeStatements.isEmpty()
				&& requestAttributeStatements.get(0) != null) {
			var assertionAttributes = requestAttributeStatements.get(0).getAttributes();
			for (Attribute attribute : assertionAttributes) {
				var namespaceUri = attribute.getName();
				if (namespaceUri != null && namespaceUri.equals(definition.getNamespaceUri())) {
					return SamlUtil.getOriginalIssuerFromAttribute(attribute);
				}
			}
		}
		return null;
	}

	private Map<Definition, List<String>> getResponseQueryElements(Assertion headerAssertion, String addressFromRequest,
			CpResponse cpResponse) {

		if (headerAssertion.getSubject().getNameID() == null || headerAssertion.getSubject().getNameID().getValue() == null) {
			throw new TechnicalException(String.format("Missing NameId from Assertion with id=%s for Address=%s",
					headerAssertion.getID(), addressFromRequest));
		}

		if (headerAssertion.getIssuer() == null) {
			throw new TechnicalException(String.format("Missing Issuer from Assertion with id=%s ", headerAssertion.getID()));
		}

		Map<Definition, List<String>> response = new HashMap<>();
		var relyingPartyConfig = RelyingParty.builder().id(addressFromRequest).build();
		var callback = new DefaultIdmStatusPolicyCallback(cpResponse);

		for (var idmService : idmServices) {
			var queryResponse = idmService.getAttributesFromIdm(
					relyingPartyConfig, cpResponse, cpResponse.getIdmLookup(), callback);
			queryResponse.ifPresent(idmResult -> DefinitionUtil.mapCpAttributeList(idmResult.getUserDetails(), response));
		}
		return response;
	}


	private CpResponse createCpResponseDto(Assertion headerAssertion, String addressFromRequest) {
		var issuer = headerAssertion.getIssuer();
		if (issuer == null) {
			throw new TechnicalException("Assertion issuer is null for Assertion with ID=" + headerAssertion.getID());
		}
		var idpIssuer = issuer.getValue();
		Map<Definition, List<String>> idpAttributes = new HashMap<>();

		// minimal processing context (WSTrust does not need state)
		var cpResponse = new CpResponse();
		if (headerAssertion.getSubject() != null && headerAssertion.getSubject().getNameID() != null) {
			cpResponse.setAttribute(CoreAttributeName.NAME_ID.getNamespaceUri(),
					headerAssertion.getSubject().getNameID().getValue());
			cpResponse.setNameId(headerAssertion.getSubject().getNameID().getValue());
		}
		cpResponse.setIssuer(idpIssuer);
		cpResponse.setAttributes(idpAttributes);

		// AttributeStatements
		if (headerAssertion.getAttributeStatements() != null && !headerAssertion.getAttributeStatements().isEmpty()) {
			var assertionAttributes = headerAssertion.getAttributeStatements().get(0).getAttributes();
			for (Attribute attribute : assertionAttributes) {
				var namespaceUri = attribute.getName();
				var values = SamlUtil.getValuesFromAttribute(attribute);
				if (namespaceUri != null && values != null && !values.isEmpty()) {
					cpResponse.setAttributes(namespaceUri, values); // free to be processed afterward
				}
			}
		}

		var homeName = relyingPartySetupService.getHomeName(idpIssuer, "", List.of(headerAssertion), cpResponse);
		cpResponse.setHomeName(homeName);

		var idmLookUp = relyingPartySetupService.getIdmLookUp(addressFromRequest, "");
		if (idmLookUp.isPresent()) {
			cpResponse.setIdmLookup(idmLookUp.get().shallowClone());
		}

		cpResponse.setClientExtId(relyingPartySetupService.getRpClientExtId(addressFromRequest, ""));
		cpResponse.setClientName(relyingPartySetupService.getRpClientName(addressFromRequest, ""));

		var authLevelAttribute = cpResponse.getAttribute(CoreAttributeName.AUTH_LEVEL.getNamespaceUri());
		if (authLevelAttribute != null) {
			cpResponse.setAuthLevel(authLevelAttribute);
		}

		cpResponse.setRpIssuer(addressFromRequest);

		Map<Definition, List<String>> originalAttributes = new HashMap<>(cpResponse.getAttributes());
		cpResponse.setOriginalAttributes(originalAttributes);

		return cpResponse;
	}

	public static String getAddressFromRequest(RequestSecurityToken requestSecurityToken) {
		Objects.requireNonNull(requestSecurityToken);
		Objects.requireNonNull(requestSecurityToken.getDOM());

		var addressFromRequest = getElementValueByTagName(
				"Address", "wsa:Address", requestSecurityToken.getDOM());

		if (addressFromRequest == null) {
			throw new RequestDeniedException("Address is missing from the request");
		}

		log.debug("Address value is={}", addressFromRequest);
		return addressFromRequest;
	}

	private static String getElementValueByTagName(String tagName, String tagNameWithNamespace, Element element) {
		var list = element.getElementsByTagName(tagName);
		if (list != null && list.getLength() > 0) {
			var subList = list.item(0).getChildNodes();

			if (subList != null && subList.getLength() > 0) {
				return subList.item(0).getNodeValue();
			}
		}
		else {
			list = element.getElementsByTagName(tagNameWithNamespace);
			var subList = list.item(0).getChildNodes();

			if (subList != null && subList.getLength() > 0) {
				return subList.item(0).getNodeValue();
			}
		}

		var msg = String.format("Could not extract %s or %s from request", tagName, tagNameWithNamespace);
		throw new TechnicalException(msg);
	}

	private void auditRstRequestFromClient(Assertion assertion, String addressFromRequest) {
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(addressFromRequest, null);
		var auditDto = new OutboundAuditMapper(trustBrokerProperties)
				.mapFromRstRequestAssertion(assertion)
				.mapFromThreadContext()
				.mapFrom(relyingParty)
				.build();
		auditService.logOutboundSamlFlow(auditDto);
	}

	private void auditRstResponseToClient(Assertion assertion, String addressFromRequest) {
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(addressFromRequest, null);
		var auditDto = new OutboundAuditMapper(trustBrokerProperties)
				.mapFromRstResponseAssertion(assertion)
				.mapFromThreadContext()
				.mapFrom(relyingParty)
				.build();
		auditService.logOutboundSamlFlow(auditDto);
	}

}
