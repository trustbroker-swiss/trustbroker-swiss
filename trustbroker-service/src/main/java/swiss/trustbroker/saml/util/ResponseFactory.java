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

package swiss.trustbroker.saml.util;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.NameID;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import swiss.trustbroker.common.config.RegexNameValue;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.saml.util.SamlUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.ConstAttributes;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.saml.dto.ResponseParameters;
import swiss.trustbroker.sessioncache.dto.StateData;

@Component
@AllArgsConstructor
@Slf4j
public class ResponseFactory {

	private final RelyingPartySetupService relyingPartySetupService;

	private final TrustBrokerProperties trustBrokerProperties;

	// high level factory method
	public Assertion createAssertion(StateData idpStateData, CpResponse cpResponse, ResponseParameters params) {
		// federated parties
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(
				params.getRpIssuerId(), params.getRpReferer());
		var claimsParty = relyingPartySetupService.getClaimsProviderSetupByIssuerId(
				cpResponse.getIssuer(), idpStateData.getReferer());

		// apply missing required parameters
		applyContextAndDefaults(idpStateData, cpResponse, relyingParty, claimsParty, params);

		// filter CP attributes on relying party side (CP side already done)
		var idpAttributesDefinition = relyingPartySetupService.getRpAttributesDefinitions(
				params.getRpIssuerId(), params.getRpReferer());
		if (idpAttributesDefinition.isEmpty()) {
			idpAttributesDefinition = relyingPartySetupService.getCpAttributeDefinitions(
					cpResponse.getIssuer(), params.getRpIssuerId());
		}

		// assemble assertion
		var attributesFromIdp =	filterAndCreateCpDefinitions(cpResponse.getAttributes(), idpAttributesDefinition);
		var constAttr = relyingParty.getConstAttributes();
		var assertion = createAssertion(attributesFromIdp, cpResponse, constAttr, params);

		// disable setting OriginalIssuer on Attribute
		var removeOriginalIssuer = !relyingParty.isDelegateOrigin();
		var homeNameOriginalIssuer = mapHomeNameIssuer(params.getHomeNameIssuerMapping(), claimsParty.getId());
		updateOriginalIssuer(assertion, params.isSetOriginalIssuerIfEmpty(), params.getCpAttrOriginIssuer(),
				removeOriginalIssuer, homeNameOriginalIssuer);

		// we use the ID as session index - store for validation
		idpStateData.setSessionIndex(assertion.getID());

		// sign assertion
		if (trustBrokerProperties.getSecurity().isDoSignAssertions()) {
			var signatureParams = relyingParty.getSignatureParametersBuilder()
					.credential(params.getCredential())
					.skinnyAssertionNamespaces(params.getSkinnyAssertionStyle())
					.build();
			SamlFactory.signAssertion(assertion, signatureParams);
		}
		return assertion;
	}

	// low level factory method, assembling everything according to RP input, CP response, configuration and state
	public static Assertion createAssertion(List<Definition> attributesFromIdp, CpResponse cpResponse,
			ConstAttributes constAttr, ResponseParameters params) {
		var assertion = OpenSamlUtil.buildAssertionObject(params.getSkinnyAssertionStyle());
		var assertionId = OpenSamlUtil.generateSecureRandomId();
		if (params.getConversationId() != null) {
			assertionId = params.getConversationId() + assertionId; // conversation extended
		}
		assertion.setID(assertionId);
		assertion.setIssueInstant(params.getIssuerInstant());
		assertion.setVersion(SAMLVersion.VERSION_20);
		assertion.setIssuer(SamlFactory.createIssuer(params.getFederationServiceIssuerId()));

		// Note that audience condition and subject confirmation use the same tolerance (default 8min)
		var nameId = SamlFactory.createNameId(params.getNameId(), cpResponse.getNameIdFormat(), null);
		var rpAuthRequestId = params.getRpAuthnRequestId();
		assertion.setSubject(SamlFactory.createSubject(nameId, rpAuthRequestId, params.getRecipientId(),
				params.getSubjectValiditySeconds()));
		assertion.setConditions(
				SamlFactory.createConditions(params.getIssuerId(), params.getAudienceValiditySeconds()));

		var attributes = createAttributes(cpResponse.getUserDetails(), params.getCpAttrOriginIssuer(),
				constAttr, attributesFromIdp, params.getRpClientName(), cpResponse.getProperties());
		var deduplicatedAttributes = SamlFactory.filterDuplicatedAttributes(attributes);
		deduplicatedAttributes = SamlFactory.dropDuplicatedAttributeFromOriginalIssuer(
				deduplicatedAttributes, params.getDropDuplicatedAttributeFromOriginalIssuer());
		var attributeStatement = SamlFactory.createAttributeStatement(deduplicatedAttributes);

		assertion.getAttributeStatements().add(attributeStatement);
		if (cpResponse.getContextClasses() != null) {
			assertion.getAuthnStatements()
					 .addAll(SamlFactory.createAuthnState(cpResponse.getContextClasses(), assertionId,
							 params.getAuthnStatementInstant()));
		}

		// audit input
		addAttributesToDtoResults(cpResponse, attributes);
		return assertion;
	}

	private void applyContextAndDefaults(StateData idpStateData, CpResponse cpResponse,
			RelyingParty relyingParty, ClaimsParty claimsParty,
			ResponseParameters params) {
		applyRpSideDefaults(idpStateData, cpResponse, relyingParty, params);

		applyFederationDefaults(cpResponse, claimsParty, params);

		applyValidityParameterDefaults(relyingParty, params);
	}

	private static void applyRpSideDefaults(StateData idpStateData, CpResponse cpResponse, RelyingParty relyingParty,
			ResponseParameters params) {
		params.setRpAuthnRequestId(idpStateData.getSpStateData().getId());
		if (params.getIssuerId() == null) {
			params.setIssuerId(idpStateData.getRpIssuer());
		}
		if (params.getRecipientId() == null) {
			params.setRecipientId(getRpRecipient(idpStateData, cpResponse));
		}
		if (params.getCredential() == null) {
			params.setCredential(relyingParty.getRpSigner());
		}
	}

	private void applyFederationDefaults(CpResponse cpResponse, ClaimsParty claimsParty, ResponseParameters params) {
		if (params.getFederationServiceIssuerId() == null) {
			var federationServiceIssuer = cpResponse.getCustomIssuer() != null ? cpResponse.getCustomIssuer() :
					trustBrokerProperties.getIssuer();
			params.setFederationServiceIssuerId(federationServiceIssuer);
		}
		if (params.getNameId() == null) {
			params.setNameId(params.isAccessRequest() ? cpResponse.getOriginalNameId() : cpResponse.getNameId());
		}
		if (params.getCpAttrOriginIssuer() == null) {
			var cpOriginalIssuer = claimsParty.getOriginalIssuer();
			params.setCpAttrOriginIssuer(cpOriginalIssuer);
		}
		if (params.getRpClientName() == null) {
			var rpClientName = relyingPartySetupService.getRpClientName(
					params.getRpIssuerId(), params.getRpReferer());
			params.setRpClientName(rpClientName);
		}
		if (params.getSkinnyAssertionStyle() == null) {
			params.setSkinnyAssertionStyle(trustBrokerProperties.getSkinnyAssertionNamespaces());
		}
	}

	private void applyValidityParameterDefaults(RelyingParty relyingParty, ResponseParameters params) {
		var now = Instant.now();
		if (params.getSubjectValiditySeconds() <= 0) {
			params.setSubjectValiditySeconds(relyingPartySetupService.getTokenLifetime(relyingParty));
		}
		if (params.getAudienceValiditySeconds() <= 0) {
			params.setAudienceValiditySeconds(relyingPartySetupService.getAudienceRestrictionLifetime(relyingParty));
		}
		if (params.getIssuerInstant() == null) {
			params.setIssuerInstant(now);
		}
		if (params.getAuthnStatementInstant() == null) {
			params.setAuthnStatementInstant(now);
		}
	}

	private static String mapHomeNameIssuer(List<RegexNameValue> homeNameIssuerMappings, String cpId) {
		if (cpId == null || CollectionUtils.isEmpty(homeNameIssuerMappings)) {
			return null;
		}
		for (var mapping : homeNameIssuerMappings) {
			if (mapping.getPattern().matcher(cpId).matches()) {
				return mapping.getValue();
			}
		}
		return null;
	}

	private static void updateOriginalIssuer(Assertion assertion, boolean setOriginalIssuerIfEmpty, String claimOriginalIssuer,
			boolean removeOriginalIssuer, String homeNameOriginalIssuer) {
		for (var as : assertion.getAttributeStatements()) {
			for (var att : as.getAttributes()) {
				if (homeNameOriginalIssuer != null && CoreAttributeName.HOME_NAME.equalsByNameOrNamespace(att.getName())) {
					SamlUtil.setOriginalIssuer(att, homeNameOriginalIssuer);
					log.debug("Using originalIssuer={} for attributeName={}", homeNameOriginalIssuer, att.getName());
				}
				else if (removeOriginalIssuer) {
					SamlUtil.removeOriginalIssuer(att);
				}
				else if (setOriginalIssuerIfEmpty && claimOriginalIssuer != null) {
					SamlUtil.setOriginalIssuerIfMissing(att, claimOriginalIssuer);
				}
			}
		}
	}

	private static String getRpRecipient(StateData idpStateData, CpResponse cpResponse) {
		// script has prio 1 to define the recipient
		if (cpResponse.getRpRecipient() != null) {
			return cpResponse.getRpRecipient();
		}
		// if subject recipient is not defined use response destination
		return getRpDestination(idpStateData, cpResponse);
	}


	public static String getRpDestination(StateData idpStateData, CpResponse cpResponse) {
		// script has prio 1 to define the destination
		if (cpResponse != null && cpResponse.getRpDestination() != null) {
			return cpResponse.getRpDestination();
		}
		// note that the RP AuthnRequest AssertionConsumerServiceUrl must have been accepted by the ACWhitelist
		return idpStateData.getSpStateData().getAssertionConsumerServiceUrl();
	}

	public static List<Definition> filterAndCreateCpDefinitions(Map<Definition, List<String>> idpConfAttributes,
			Collection<Definition> idpAttributes) {
		if (idpAttributes == null) {
			throw new TechnicalException("Missing IDP response attributes");
		}
		List<Definition> respIdpAttributes = new ArrayList<>();
		for (Definition definition : idpAttributes) {
			var attributeValues = getAttributeValues(idpConfAttributes, definition);
			if (!attributeValues.isEmpty()) {
				var newDefinition = definition.toBuilder()
					.values(attributeValues)
					.build();
				respIdpAttributes.add(newDefinition);
			}
		}
		return respIdpAttributes;
	}

	private static List<String> getAttributeValues(Map<Definition, List<String>> userDetails, Definition definition) {
		return userDetails.entrySet().stream()
				.filter(userAttribute ->
						userAttribute.getKey().equalsByNameOrNamespace(definition))
				.map(Map.Entry::getValue)
				.findFirst()
				.orElse(Collections.emptyList());

	}

	public static void filterCpAttributes(CpResponse cpResponseDTO, List<Definition> cpAttributeDefinitions) {
		cpResponseDTO.getAttributes().entrySet()
					 .removeIf(att -> attributeHasNoDefinition(att.getKey(), cpAttributeDefinitions));
	}

	private static boolean attributeHasNoDefinition(Definition key, List<Definition> cpAttributeDefinitions) {
		for (Definition definition : cpAttributeDefinitions) {
			if (key.equalsByNameOrNamespace(definition)) {
				return false;
			}
		}
		return true;
	}

	public static List<Attribute> createCpResponseAttributes(String attrOriginIssuer, List<Definition> attributesForIdp,
			String clientName) {
		List<Attribute> attributeList = new ArrayList<>();
		if (attributesForIdp == null) {
			return attributeList;
		}
		for (Definition idpAttribute : attributesForIdp) {
			String nameURI = idpAttribute.getNamespaceUri();
			var values = idpAttribute.getMultiValues();
			if (nameURI != null) {
				nameURI = SamlFactory.replaceClientNameInUri(nameURI, clientName);
				attributeList.add(SamlFactory.createAttribute(nameURI, values, attrOriginIssuer));
			}
		}
		return attributeList;
	}

	public static List<Attribute> createUserDetailsAttributes(Map<Definition, List<String>> userDetails, String clientName) {
		List<Attribute> attributeList = new ArrayList<>();
		if (userDetails == null) {
			return attributeList;
		}
		for (Map.Entry<Definition, List<String>> entry : userDetails.entrySet()) {
			String namespaceUri = entry.getKey().getNamespaceUri();
			String name = entry.getKey().getName();
			if (namespaceUri != null) {
				namespaceUri = SamlFactory.replaceClientNameInUri(namespaceUri, clientName);
				attributeList.add(SamlFactory.createResponseAttribute(namespaceUri, entry.getValue()));
			}
			else if (name != null) {
				attributeList.add(SamlFactory.createResponseAttribute(name, entry.getValue()));
			}
		}

		return attributeList;
	}

	static Collection<Attribute> createAttributes(Map<Definition, List<String>> userDetailsFromIdm,
			String attrOriginIssuer, ConstAttributes constAttr, List<Definition> idpAttributes, String clientName,
			Map<Definition, List<String>> properties) {

		// assemble all output SAML attributes in the order of 'last-one-wins' in a multiValued=false handling
		var attributeList = new ArrayList<Attribute>();
		attributeList.addAll(createCpResponseAttributes(attrOriginIssuer, idpAttributes, clientName));
		attributeList.addAll(createUserDetailsAttributes(userDetailsFromIdm, clientName));
		attributeList.addAll(createUserDetailsAttributes(properties, clientName));
		attributeList.addAll(createConstAttributes(constAttr, clientName));
		return attributeList;
	}


	public static List<Attribute> createConstAttributes(ConstAttributes constAttr, String clientName) {
		List<Attribute> attributeList = new ArrayList<>();
		if (constAttr == null || constAttr.getAttributeDefinitions() == null) {
			return attributeList;
		}
		for (Definition definition : constAttr.getAttributeDefinitions()) {
			var nameURI = definition.getNamespaceUri();
			var values = definition.getMultiValues();
			if (nameURI != null && values != null && !values.isEmpty()) {
				nameURI = SamlFactory.replaceClientNameInUri(nameURI, clientName);
				attributeList.add(SamlFactory.createAttribute(nameURI, values, null));
			}
		}
		return attributeList;
	}

	private static void addAttributesToDtoResults(CpResponse cpResponse, Collection<Attribute> attributes) {
		attributes.forEach(attribute -> cpResponse.setResult(attribute.getName(),
				SamlFactory.attributeValueToStrings(attribute.getAttributeValues())));
	}

	public static NameID createNameId(CpResponse cpResponse) {
		if (cpResponse != null && cpResponse.getNameId() != null && cpResponse.getNameIdFormat() != null) {
			return SamlFactory.createNameId(cpResponse.getNameId(), cpResponse.getNameIdFormat(), null);
		}
		return null;
	}

}
