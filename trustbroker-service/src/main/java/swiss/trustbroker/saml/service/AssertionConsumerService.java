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

package swiss.trustbroker.saml.service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.security.credential.Credential;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import swiss.trustbroker.api.announcements.dto.Announcement;
import swiss.trustbroker.api.announcements.service.AnnouncementService;
import swiss.trustbroker.api.homerealmdiscovery.service.HrdService;
import swiss.trustbroker.audit.service.AuditService;
import swiss.trustbroker.audit.service.InboundAuditMapper;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.saml.dto.SamlBinding;
import swiss.trustbroker.common.saml.dto.SignatureContext;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.common.saml.util.EncryptionUtil;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlIoUtil;
import swiss.trustbroker.common.saml.util.SamlUtil;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.ClaimsProvider;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderRelyingParty;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.Qoa;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.SecurityPolicies;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.homerealmdiscovery.util.OperationalUtil;
import swiss.trustbroker.oidc.session.OidcSessionSupport;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.saml.dto.ResponseData;
import swiss.trustbroker.saml.dto.RpRequest;
import swiss.trustbroker.saml.dto.UiObject;
import swiss.trustbroker.saml.util.AssertionValidator;
import swiss.trustbroker.saml.util.ResponseFactory;
import swiss.trustbroker.saml.util.SamlStatusCode;
import swiss.trustbroker.saml.util.SamlValidationUtil;
import swiss.trustbroker.script.service.ScriptService;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.sessioncache.service.StateCacheService;
import swiss.trustbroker.sso.service.SsoService;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.HrdSupport;
import swiss.trustbroker.util.WebSupport;

@Service
@AllArgsConstructor
@Slf4j
public class AssertionConsumerService {

	private final TrustBrokerProperties trustBrokerProperties;

	private final RelyingPartyDefinitions relyingPartyDefinitions;

	private final RelyingPartySetupService relyingPartySetupService;

	private final StateCacheService stateCacheService;

	private final ScriptService scriptService;

	private final SsoService ssoService;

	private final AuditService auditService;

	private final AnnouncementService announcementService;

	private final HrdService hrdService;

	public CpResponse handleSuccessCpResponse(ResponseData<Response> responseData) {
		// message assertions
		var response = responseData.getResponse();
		OpenSamlUtil.checkResponseLimitations(response, "CP response processing");

		// session state
		var idpStateData = retrieveValidStateDataForResponse(responseData);

		// validation
		String responseIssuer = responseData.getResponse().getIssuer().getValue();
		String referrer = idpStateData.getReferer();
		var claimsParty = relyingPartySetupService.getClaimsProviderSetupByIssuerId(responseIssuer, referrer);
		var encryptionTrustCredentials = relyingPartySetupService.getClaimEncryptionTrustCredentials(responseIssuer, referrer);
		List<Assertion> responseAssertions = getResponseAssertions(responseData.getResponse(), encryptionTrustCredentials);
		validateResponse(true, responseData, idpStateData, claimsParty, responseAssertions);

		log.debug("CP response assertion validated");

		// internal processing context
		var cpResponse = extractCpResponseDto(response, responseAssertions);

		// Known attributes from config as a default before we offer the opportunity to modify it in the CP/RP BeforeIdm scripts
		cpResponse.setHomeName(
				relyingPartySetupService.getHomeName(responseIssuer, referrer, responseAssertions, cpResponse));

		// Make RP issuer available to scripts in case AfterIdm hooks need to have it as input
		cpResponse.setRpIssuer(idpStateData.getRpIssuer());
		cpResponse.setClientName(relyingPartySetupService.getRpClientName(idpStateData.getRpIssuer(), null));
		cpResponse.setCustomIssuer(trustBrokerProperties.getIssuer()); // allows to use it as input too

		// save some AuthnRequest related HTTP layer data
		if (idpStateData.getSpStateData() != null) {
			cpResponse.setRpContext(idpStateData.getSpStateData().getRpContext());
			// propagate applicationName and OIDC client_id for scripting
			cpResponse.setOidcClientId(idpStateData.getRpOidcClientId());
			cpResponse.setApplicationName(idpStateData.getRpApplicationName());
		}

		// Scripts BeforeIdm CP side
		scriptService.processCpBeforeIdm(cpResponse, response, claimsParty.getId(), referrer);

		// Original CpResponse before filtering the attributes
		cpResponse.setOriginalAttributes(new HashMap<>(cpResponse.getAttributes()));

		// Filter CP attributes
		List<Definition> cpAttributeDefinitions =
				relyingPartySetupService.getCpAttributeDefinitions(cpResponse.getIssuer(), "");
		if (!cpAttributeDefinitions.isEmpty()) {
			ResponseFactory.filterCpAttributes(cpResponse, cpAttributeDefinitions);
		}

		String rpIssuer = idpStateData.getRpIssuer();
		var idmLookUp = relyingPartySetupService.getIdmLookUp(rpIssuer, referrer);
        idmLookUp.ifPresent(idmLookup -> cpResponse.setIdmLookup(idmLookup.shallowClone()));

		//set clientExtId
		cpResponse.setClientExtId(relyingPartySetupService.getRpClientExtId(rpIssuer, ""));

		// scripts BeforeIdm RP side (see test DeriveClaimProviderNameFromNameIdFormat.groovy for an example to derive HomeName)
		scriptService.processRpBeforeIdm(cpResponse, response, rpIssuer, referrer);

		// session for SSO
		idpStateData.setCpResponse(cpResponse);
		stateCacheService.save(idpStateData, this.getClass().getSimpleName());

		return cpResponse;
	}

	private static List<Assertion> getResponseAssertions(Response response, List<Credential> encryptionTrustCredentials) {
		List<Assertion> assertions = new ArrayList<>();
		var issuerId = "MISSING-CP-ISSUER-ID";
		if (response.getIssuer() != null) {
			issuerId = response.getIssuer().getValue();
		}
		if (CollectionUtils.isNotEmpty(response.getEncryptedAssertions())) {
			for (EncryptedAssertion encryptedAssertion : response.getEncryptedAssertions()) {
				Assertion assertion = EncryptionUtil.decryptAssertion(
						encryptedAssertion, encryptionTrustCredentials, response.getID(), issuerId);
				assertions.add(assertion);
			}
		}
		else {
			assertions = response.getAssertions();
		}
		return assertions;
	}

	public CpResponse handleFailedCpResponse(ResponseData<Response> responseData) {
		// message assertions
		OpenSamlUtil.checkResponsePresent(responseData.getResponse(), "CP failed response processing");

		// session state
		var idpStateData = retrieveValidStateDataForResponse(responseData);

		// validation
		var cpResponse = validateAndGetCpResponse(responseData, idpStateData);

		// take over displaying stuff
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(
				idpStateData.getRpIssuer(),
				idpStateData.getRpReferer());
		var flows = relyingParty.getFlows();
		log.debug("Checking {} FlowPolicies of rpIssuerId={}", flows.size(), relyingParty.getId());
		for (var flowPolicy : flows) {
			var samlCode = SamlStatusCode.addNamespace(trustBrokerProperties.getSaml(),
					flowPolicy.getId(), flowPolicy.getNamespacePrefix());
			if (handleResponderErrors(responseData.getResponse(), StatusCode.RESPONDER, samlCode, trustBrokerProperties)) {
				log.debug("Responder error handled according to flowPolicy={}", flowPolicy);
				if (flowPolicy.showErrorPage()) {
					cpResponse.abort(StatusCode.RESPONDER, flowPolicy);
					// state still required for interactive error handling / showing support page details
					return cpResponse;
				}
			}
		}

		stateCacheService.invalidate(idpStateData, this.getClass().getSimpleName());
		return cpResponse;
	}

	static boolean handleResponderErrors(Response response,
			String requiredStatus, String requiredNestedStatus, TrustBrokerProperties trustBrokerProperties) {
		var featureEnabled = trustBrokerProperties.isHandleResponderErrors();
		var statusCode = OpenSamlUtil.getStatusCode(response);
		var nestedStatusCode = OpenSamlUtil.getNestedStatusCode(response);
		var statusMessage = OpenSamlUtil.getStatusMessage(response);
		var result = featureEnabled &&
				(requiredStatus == null || requiredStatus.equals(statusCode)) &&
				((nestedStatusCode != null &&
						nestedStatusCode.equals(requiredNestedStatus)) ||
						(statusMessage != null && statusMessage.equals(requiredNestedStatus)));
		log.debug("Deciding responder display: featureEnabled={} requiredStatus={} statusCode={} statusMessage={} " +
						"nestedStatusCode={} result={}",
				featureEnabled,
				requiredStatus,
				statusCode,
				statusMessage,
				nestedStatusCode,
				result);
		return result;
	}

	private StateData retrieveValidStateDataForResponse(ResponseData<Response> responseData) {
		var relayState = responseData.getRelayState();
		SamlValidationUtil.validateRelayState(responseData);
		var idpStateData = stateCacheService.find(relayState, this.getClass().getSimpleName());
		AssertionValidator.validCpSession(idpStateData);
		return idpStateData;
	}

	private void validateResponse(boolean expectSuccess, ResponseData<Response> responseData, StateData idpStateData,
			ClaimsParty claimsParty, List<Assertion> responseAssertions) {
		validateBinding(claimsParty, responseData.getBinding());
		String existingRelayState = idpStateData.getRelayState();
		List<Credential> claimTrustCred = claimsParty.getCpTrustCredential();
		var expectedAudienceId = claimsParty.getAuthnRequestIssuerId();
		var expectedValues = AssertionValidator.ExpectedAssertionValues
				.builder()
				.expectedIssuer(idpStateData.getIssuer())
				.expectedAudience(expectedAudienceId)
				.expectSuccess(expectSuccess)
				.expectedRelayState(existingRelayState)
				.build();
		AssertionValidator.validateResponse(responseData, responseAssertions, claimTrustCred,
				trustBrokerProperties, claimsParty.getSecurityPolicies(), expectedValues);
	}

	private static void validateBinding(ClaimsParty claimsParty, SamlBinding binding) {
		if (!claimsParty.isValidInboundBinding(binding)) {
			throw new RequestDeniedException(String.format("ClaimsParty cpIssuerId=%s does not support inbound binding=%s",
					claimsParty.getId(), binding));
		}
	}

	private static CpResponse extractCpResponseDto(Response response, List<Assertion> assertions) {
		var cpResponse = new CpResponse();

		// assertions input (actually only one, we throw an exception if list.size > 1 before)
		// for multiple assertions we would need to also support that on the CpResponse to prevent losing data
		for (Assertion assertion : assertions) {

			// Subject
			extractSubjectAttributes(cpResponse, assertion);

			// AuthnStatement
			List<AuthnStatement> authnStatements = assertion.getAuthnStatements();
			if (authnStatements != null && !authnStatements.isEmpty() && authnStatements.get(0).getAuthnContext() != null) {
				cpResponse.setContextClasses(getContextClassRefsFromStatement(authnStatements));
			}

			// AttributeStatements
			if (CollectionUtils.isEmpty(assertion.getAttributeStatements())) {
				log.debug("Ignoring AttributeStatements={}", assertion.getAttributeStatements());
				continue;
			}
			List<Attribute> assertionAttributes = assertion.getAttributeStatements().get(0).getAttributes();
			for (Attribute attribute : assertionAttributes) {
				var namespaceUri = attribute.getName();
				var values = SamlUtil.getValuesFromAttribute(attribute);
				if (namespaceUri == null || values == null || values.isEmpty()) {
					log.debug("Ignoring namespaceUri={} value={}", namespaceUri, values);
					continue;
				}
				cpResponse.setAttributes(namespaceUri, values); // free to be processed afterwards
				if (CoreAttributeName.AUTH_LEVEL.getNamespaceUri().equals(namespaceUri)) {
					cpResponse.setAuthLevel(values.get(0));
					log.debug("Got authLevel={} from cpIssuer={}", cpResponse.getAuthLevel(),
							response.getIssuer().getValue());
				}
			}

		}

		// all the rest from CP
		cpResponse.setInResponseTo(response.getInResponseTo());
		cpResponse.setIssuer(response.getIssuer().getValue());
		cpResponse.setDestination(response.getDestination());

		return cpResponse;
	}

	private static List<String> getContextClassRefsFromStatement(List<AuthnStatement> authnStatements) {
		var authnContextClassRef = authnStatements.get(0).getAuthnContext().getAuthnContextClassRef();
		return authnContextClassRef != null && authnContextClassRef.getURI() != null ?
				List.of(authnContextClassRef.getURI()) : Collections.emptyList();
	}

	private static void extractSubjectAttributes(CpResponse cpResponse, Assertion assertion) {
		if (assertion == null || assertion.getSubject() == null) {
			if (log.isDebugEnabled()) {
				log.debug("Assertion={} Subject=null ignored, not mapping subject data",
						OpenSamlUtil.samlObjectToString(assertion, true));
			}
			return;
		}

		// map subject to CpResponse bean, so we can access data in scripting
		// NOTE: This also makes the name identifier SAML attribute available on OIDC side
		var subject = assertion.getSubject();
		var nameId = subject.getNameID().getValue();
		cpResponse.setNameId(nameId);
		cpResponse.setOriginalNameId(nameId);
		cpResponse.setNameIdFormat(SamlUtil.getAssertionNameIDFormat(assertion));
		cpResponse.setAttribute(CoreAttributeName.NAME_ID.getNamespaceUri(), nameId);
		if (CollectionUtils.isNotEmpty(subject.getSubjectConfirmations())) {
			cpResponse.setSubjectConfirmationMethod(subject.getSubjectConfirmations().get(0).getMethod());
		}
	}

	public RpRequest handleRpAuthnRequest(AuthnRequest authnRequest, HttpServletRequest httpRequest, StateData stateData) {
		if (authnRequest == null) {
			throw new RequestDeniedException("RP AuthnRequest is missing!");
		}

		// UI dispatch
		var rpIssuer = authnRequest.getIssuer().getValue();
		var applicationName = authnRequest.getProviderName();
		var result = createUiObjects(rpIssuer, authnRequest.getID(), applicationName, httpRequest, stateData);

		// track RPs
		auditAuthnRequestFromRp(authnRequest, httpRequest, stateData);

		// hook to validate the SAML directly (cannot be done in BeforeHrd because eof device redirects
		scriptService.processRequestValidation(result, httpRequest, authnRequest);

		return result;
	}

	private void auditAuthnRequestFromRp(AuthnRequest authnRequest, HttpServletRequest request, StateData stateData) {
		var relyingParty = relyingPartySetupService
				.getRelyingPartyByIssuerIdOrReferrer(authnRequest.getIssuer().getValue(), null, true);
		var auditDto = new InboundAuditMapper(trustBrokerProperties)
				.mapFrom(stateData)
				.mapFrom(authnRequest)
				.mapFrom(request)
				.mapFrom(relyingParty)
				.build();
		auditService.logInboundSamlFlow(auditDto);
	}

	private RpRequest createUiObjects(String rpIssuer, String requestId, String applicationName,
									  HttpServletRequest httpRequest, StateData stateData) {
		var referer = WebUtil.getHeader(HttpHeaders.REFERER, httpRequest);
		return renderUI(rpIssuer, referer, applicationName, httpRequest, requestId, stateData);
	}

	// This method decides what we have in the SAML POST form target. Priorities:
	// AuthnRequest.AssertionConsumerServiceUrl:
	// - Incoming AuthnRequest.AssertionConsumerServiceUrl (authorized against ACWhitelist in AssertionValidator)
	// - Best matching entry from ACWhitelist when the AuthnRequest just contains an Issuer ID
	// Note that in CpResponse this can be overridden:
	// - CpResponse.rpDestination for the SAMl Response.Destination
	// - CpResponse.rpRecipient for the Assertion.SubjectConfirmationData.Recipient
	// HTTP Header:
	// - HTTP Referer is best matched against RP ACWhitelist picking first entry that contains the Referer value
	// - HTTP Origin was dropped because we actually never used it anywhere an ambiguity hurts here
	String getAssertionConsumerServiceUrl(final String consumerUrl,
			final String referer, final String origin, RelyingParty relyingParty) {
		var acUrls = relyingParty != null && relyingParty.getAcWhitelist() != null ?
				relyingParty.getAcWhitelist().getAcUrls() : new ArrayList<String>();

		var rpIssuer = relyingParty != null ? relyingParty.getId() : null;
		if (log.isDebugEnabled()) {
			log.debug("Checking AuthRequest from rpIssuer={} with consumerUrl={} referer={} origin={} against ACWhitelist={}",
					rpIssuer, consumerUrl, referer, origin, Arrays.toString(acUrls.toArray()));
		}

		//  may be signed AuthnRequest
		var consumer = acUrls.stream().filter(acurl -> acurl.equals(consumerUrl)).findFirst();

		// internal AuthnRequest for monitoring
		if (consumer.isEmpty() && consumerUrl != null && consumerUrl.startsWith(ApiSupport.MONITORING_ACS_URL)) {
			consumer = Optional.of(ApiSupport.MONITORING_ACS_URL);
		}

		// unsigned HTTP headers
		if (consumer.isEmpty() && referer != null) {
			consumer = acUrls.stream().filter(acurl -> acurl.startsWith(referer)).findFirst();
		}
		if (consumer.isEmpty() && origin != null) {
			consumer = acUrls.stream().filter(acurl -> acurl.startsWith(origin)).findFirst();
		}

		// block
		if (consumer.isEmpty()) {
			if (!trustBrokerProperties.getSecurity().isValidateAcs()) {
				log.warn("trustbroker.config.security.validateAcs=false: Accepting AssertionConsumerServiceUrl={} "
								+ " httpReferer={} and origin={} not having a match in ACWhitelist ACWhitelist={} for rpIssuer={}",
						consumerUrl, referer, origin, Arrays.toString(acUrls.toArray()), rpIssuer);
				return consumerUrl;
			}
			throw new RequestDeniedException(String.format("Got a SAML message with AssertionConsumerServiceUrl=%s "
							+ "httpReferer=%s and origin=%s not having a match in ACWhitelist ACWhitelist=%s."
							+ " Please add an entry to rpIssuer=%s and in case referer is null fix RP to send it or an ACSUrl "
							+ "instead.",
					consumerUrl, referer, origin, Arrays.toString(acUrls.toArray()), rpIssuer));
		}

		return consumer.get();
	}

	// In the discontinued stealth mode we also needed to save this state as well to be able to analyse the SAMLResponse
	public StateData saveState(AuthnRequest authnRequest, HttpServletRequest request,
			RelyingParty relyingParty, Optional<StateData> ssoState, SamlBinding binding) {
		// without a consumer URL we at least need something from the config
		var referer = WebUtil.getHeader(HttpHeaders.REFERER, request);
		var rpIssuer = WebUtil.getHeader(HttpHeaders.ORIGIN, request);
		var ascUrl = getAssertionConsumerServiceUrl(
				authnRequest.getAssertionConsumerServiceURL(), referer, rpIssuer, relyingParty);
		var initiatedByArtifactBinding = binding == SamlBinding.ARTIFACT;
		return saveState(authnRequest, ascUrl, referer, request, ssoState, relyingParty.getQoa(), initiatedByArtifactBinding);
	}

	// Internal method used by monitoring only aside from above as ACL check is skipped
	private StateData saveState(AuthnRequest authnRequest, String ascUrl, String referer, HttpServletRequest request,
			Optional<StateData> ssoState, Qoa qoa, boolean initiatedViaArtifactBinding) {
		// RP using relay state?
		var spRelayState = request.getParameter(SamlIoUtil.SAML_RELAY_STATE);
		if (log.isDebugEnabled()) {
			log.debug("Inbound SP RelayState: {}", StringUtil.clean(spRelayState));
		}

		// incoming AuthnRequest.ID initially used as session ID
		var authnRequestId = authnRequest.getID();
		SamlUtil.validateSessionId(authnRequestId, "AuthnRequestID used as SP state ID");

		// remember RP for AuthnRequest/response exchange OR as initiator for SSO
		var rpContexts = WebSupport.getHttpContext(request, trustBrokerProperties.getNetwork());
		var contextClasses = getContextClasses(OpenSamlUtil.extractAuthnRequestContextClasses(authnRequest), qoa);
		var comparisonType = getComparisonType(authnRequest);
		var providerName = authnRequest.getProviderName();

		// support correlation with OIDC invocation in scripts too on SAML side (if login was trigger by client_id)
		var oidcClientId = OidcSessionSupport.getSamlExchangeAcsUrlClientId(ascUrl);

		// sp state data
		var spStateData = StateData.builder()
				.id(authnRequestId)
				.lastConversationId(authnRequest.getID())
				.issuer(authnRequest.getIssuer().getValue())
				.referer(referer)
				.rpContext(rpContexts)
				.relayState(spRelayState)
				.contextClasses(contextClasses)
				.comparisonType(comparisonType)
				.assertionConsumerServiceUrl(ascUrl)
				.applicationName(providerName)
				.oidcClientId(oidcClientId)
				.issueInstant(authnRequest.getIssueInstant().toString())
				.initiatedViaArtifactBinding(initiatedViaArtifactBinding)
				.build();

		StateData stateData;
		if (ssoState.isEmpty()) {
			var relayState = ssoService.generateRelayState();
			// using relay state as state ID (must surely be a valid ID)
			SamlUtil.validateSessionId(relayState, "XTB relay state used as session ID");
			stateData = StateData.builder()
					.id(relayState)
					.relayState(relayState)
					.build();
			log.debug("No SSO or no SSO state yet, created new one: {}", relayState);
		}
		else {
			stateData = ssoState.get();
			log.debug("Using existing SSO state {}", stateData.getId());
		}

		// refresh on sessiondb
		stateData.setSpStateData(spStateData);

		// Keep the following in sync with SsoService.copyToSsoStateAndInvalidateAuthnRequestState
		stateData.setLastConversationId(authnRequest.getID()); // conversation the same for CP and RP side

		stateData.setForceAuthn(OpenSamlUtil.isForceAuthnRequest(authnRequest));
		stateData.setSignedAuthnRequest(authnRequest.isSigned());

		stateCacheService.save(stateData, this.getClass().getSimpleName());
		return stateData;
	}

	List<String> getContextClasses(List<String> requestContextClasses, Qoa qoa) {
		if (requestContextClasses.isEmpty() && qoa != null && !qoa.getClasses().isEmpty()) {
			return qoa.getClasses();
		}
		return requestContextClasses;
	}

	// Specified comparison operator, so we have to pass it on
	String getComparisonType(AuthnRequest authnRequest) {
		if (authnRequest != null && authnRequest.getRequestedAuthnContext() != null &&
				authnRequest.getRequestedAuthnContext().getComparison() != null) {
			return authnRequest.getRequestedAuthnContext().getComparison().toString();
		}
		return null;
	}

	private static List<String> getRpContextClasses(StateData stateData) {
		List<String> contextClasses = new ArrayList<>();
		if (stateData != null && stateData.getRpContextClasses() != null) {
			contextClasses.addAll(stateData.getRpContextClasses());
		}
		return contextClasses;
	}

	// The CP list is influenced by the following resolution:
	// - SetupRP.xml containing a direct mapping of 1 to n CPs
	// - Check against Client_Network header to support silent routing in case of 1:1 mapping with INTRANET or INTERNET
	// - Check urltester header/cookie to directly identify a CP, so we skip the HRD screen
	public RpRequest getRpRequestDetails(
			String rpIssuer, String referer, String applicationName,
			HttpServletRequest request, String requestId, StateData stateData) {
		// output
		List<ClaimsProviderRelyingParty> cpMappings = new ArrayList<>();

		// request mapping towards processing
		var rpRequest = RpRequest.builder()
								 .claimsProviders(cpMappings) // pass on per request handling copy, uiObjects stay empty (render later)
								 .rpIssuer(rpIssuer)
								 .requestId(requestId)
								 .referer(referer)
								 .contextClasses(getRpContextClasses(stateData))
								 .applicationName(applicationName)
								 .build();

		// pre-conditions
		if (StringUtils.isEmpty(rpIssuer) && StringUtils.isEmpty(referer)) {
			log.warn("Cannot derive RP setup without any input data");
			return rpRequest;
		}

		// SetupRp.xml directly
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(rpIssuer, referer);
		if (relyingParty != null && relyingParty.getClaimsProviderMappings() != null &&
				relyingParty.getClaimsProviderMappings().getClaimsProviderList() != null) {
			log.debug("Found {} entries for rpIssuer='{}' and referrer='{}' in SetupRP",
					cpMappings.size(), rpIssuer, referer);
			cpMappings.addAll(relyingParty.getClaimsProviderMappings().getClaimsProviderList());
		}

		// we should have something now
		if (cpMappings.isEmpty()) {
			throw new RequestDeniedException(String.format(
					"Missing SetupRP.xml/*/ClaimsProviderMappings entries for rpIssuer='%s' referrer='%s' (cannot dispatch CP)",
					rpIssuer, referer));
		}

		// apply urltester hint, overrides network and any other selection, so we can simulate INTRANET even if only on INTERNET
		final var cpSelectionHint = HrdSupport.getClaimsProviderHint(request, trustBrokerProperties);

		// Allow script to override manipulate cpMappings before we do it internally
		scriptService.processHrdSelection(rpRequest, request);

		// throw out all CPs not valid for current network, cookies, ....
		cpMappings = new ArrayList<>(rpRequest.getClaimsProviders()); // in case script has constructed a new (immutable) list
		cpMappings = HrdSupport.reduceClaimsProviderMappings(request, rpIssuer, applicationName,
				cpSelectionHint, cpMappings, trustBrokerProperties, hrdService);
		rpRequest.setClaimsProviders(cpMappings); // because our own reduction logic also might create a new list

		// If groovy script manipulates the classrefs we need dto make sure that this gets persisted
		updateStateData(stateData, rpRequest);

		return rpRequest;
	}

	private void updateStateData(StateData stateData, RpRequest rpRequest) {
		if (stateData != null && stateData.getSpStateData() != null) {
			var stateContextClasses = stateData.getRpContextClasses();
			if (!CollectionUtils.isEqualCollection(stateContextClasses, rpRequest.getContextClasses())) {
				stateData.getSpStateData().setContextClasses(rpRequest.getContextClasses());
				stateCacheService.save(stateData, this.getClass().getSimpleName());
			}
		}
	}

	// Show HRD screen when we have multiple CPs
	public RpRequest renderUI(String rpIssuer, String referer, String applicationName,
							  HttpServletRequest httpRequest, String requestId,
			StateData stateData) {
		var rpRequest = getRpRequestDetails(rpIssuer, referer, applicationName, httpRequest, requestId, stateData);
		var uiObjects = new ArrayList<UiObject>();

		var globalDisabledAppNames = getGlobalDisabledAppNames(rpIssuer, referer, httpRequest, rpRequest);

		rpRequest.getClaimsProviders().forEach(mapp -> {
			var claimsProvider = relyingPartyDefinitions.getClaimsProviderById(mapp.getId());
			uiObjects.add(createUIElement(claimsProvider, globalDisabledAppNames));
		});
		rpRequest.setUiObjects(uiObjects);

		return rpRequest;
	}

	private ArrayList<String> getGlobalDisabledAppNames(String rpIssuer, String referer, HttpServletRequest httpRequest,
			RpRequest rpRequest) {
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(rpIssuer, referer);
		var skipUserFeatures = OperationalUtil.skipUserFeatures(rpRequest, httpRequest, trustBrokerProperties); // skip
		// disabling
		var globalAnnouncements = new ArrayList<String>();
		if (announcementService.showAnnouncements(relyingParty.getAnnouncement()) && !skipUserFeatures) {
			for (Announcement announcement : announcementService.getGlobalAnnouncements()) {
				if (announcement.getApplicationAccessible() != null && !announcement.getApplicationAccessible()) {
					globalAnnouncements.add(getGlobalAppName(announcement.getApplicationName()));
				}
			}
		}
		return globalAnnouncements;
	}

	private static String getGlobalAppName(String applicationName) {
		if (applicationName == null) {
			return "None";
		}
		String[] appNameElements = applicationName.split("-");
		int length = appNameElements.length;
		return appNameElements[length - 1];
	}

	// Retrieve title for the tile, fallback handling if there are no (matching) language packs.
	private static String getTitle(ClaimsProvider claimsProvider) {
		String title = claimsProvider.getDescription();
		if (title == null) {
			title = claimsProvider.getName();
		}
		if (title == null) {
			title = claimsProvider.getTitle();
		}
		if (title == null) {
			title = claimsProvider.getId();
		}
		return title;
	}

	private static UiObject createUIElement(ClaimsProvider claimsProvider, ArrayList<String> globalDisabledAppNames) {
		// UI data for the frontend
		var uiObject = new UiObject();
		uiObject.setUrn(claimsProvider.getId());
		uiObject.setImage(claimsProvider.getImg());
		uiObject.setButton(claimsProvider.getButton());
		uiObject.setTitle(getTitle(claimsProvider));
		uiObject.setName(claimsProvider.getDescription());
		uiObject.setShortcut(claimsProvider.getShortcut());
		uiObject.setColor(claimsProvider.getColor());
		uiObject.setTileTitle(getTileTile(claimsProvider));
		uiObject.setDisabled(false);
		if (isIdpDisabled(claimsProvider.getId(), globalDisabledAppNames)) {
			uiObject.setDisabled(true);
		}
		return uiObject;
	}

	private static boolean isIdpDisabled(String id, ArrayList<String> globalDisabledAppNames) {
		if (globalDisabledAppNames.isEmpty()) {
			return false;
		}
		for (String announcementId : globalDisabledAppNames) {
			if (removeIdSpecChar(id).contains(announcementId.toUpperCase())) {
				return true;
			}
		}
		return false;
	}

	private static String removeIdSpecChar(String id) {
		return id.replace("-", "").toUpperCase();
	}

	private static String getTileTile(ClaimsProvider claimsProvider) {
		if (claimsProvider.getTitle() != null) {
			return claimsProvider.getTitle();
		}
		if (claimsProvider.getName() != null) {
			return claimsProvider.getName();
		}
		if (claimsProvider.getDescription() != null) {
			return claimsProvider.getDescription();
		}
		return claimsProvider.getId();
	}

	public void validateAuthnRequest(AuthnRequest authnRequest, HttpServletRequest request,
			SignatureContext signatureContext, SecurityPolicies securityPolicies) {
		// pre conditions
		if (authnRequest == null) {
			throw new RequestDeniedException("RP AuthnRequest is missing!");
		}

		// validation
		if (trustBrokerProperties.getSecurity().isValidateAuthnRequest()) {
			var issuer = authnRequest.getIssuer().getValue();
			var referer = WebUtil.getHeader(org.springframework.http.HttpHeaders.REFERER, request);
			var trustCredentials = relyingPartySetupService.getRelyingTrustCredentials(issuer, referer);
			var acWhiteList = relyingPartySetupService.getAcWhiteList(authnRequest.getIssuer().getValue(), null);
			AssertionValidator.validateAuthnRequest(authnRequest, trustCredentials, acWhiteList, trustBrokerProperties,
					securityPolicies, signatureContext);
		}
		else {
			log.error("trustbroker.config.security.validateAuthnRequest=false: Security on AuthnRequest disabled!!!");
		}
	}

	public StateData requestEnterpriseIdp(ResponseData<Response> responseData) {
		OpenSamlUtil.checkResponsePresent(responseData.getResponse(), "CP failed response processing");

		var idpStateData = retrieveValidStateDataForResponse(responseData);
		log.debug("User requested context switch to Enterprise. IdpIssuer={}, responseId={}", idpStateData.getIssuer(),
				responseData.getResponse().getID());

		validateAndGetCpResponse(responseData, idpStateData);

		return idpStateData;
	}

	private CpResponse validateAndGetCpResponse(ResponseData<Response> responseData, StateData idpStateData) {
		String responseIssuer = responseData.getResponse().getIssuer().getValue();
		String referrer = idpStateData.getReferer();
		var claimsParty = relyingPartySetupService.getClaimsProviderSetupByIssuerId(responseIssuer, referrer);
		var encryptionTrustCredentials = claimsParty.getCpEncryptionTrustCredentials();
		List<Assertion> responseAssertions = getResponseAssertions(responseData.getResponse(), encryptionTrustCredentials);
		validateResponse(false, responseData, idpStateData, claimsParty, responseAssertions);

		// internal processing context
		var cpResponse = extractCpResponseDto(responseData.getResponse(), responseAssertions);
		cpResponse.setRpContext(idpStateData.getRpContext());

		// session for SSO
		idpStateData.setCpResponse(cpResponse);
		return cpResponse;
	}

}
