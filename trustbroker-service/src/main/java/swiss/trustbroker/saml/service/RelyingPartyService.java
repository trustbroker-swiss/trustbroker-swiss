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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.xml.security.utils.EncryptionConstants;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.SessionIndex;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.security.credential.Credential;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import swiss.trustbroker.api.accessrequest.dto.AccessRequestHttpData;
import swiss.trustbroker.api.accessrequest.service.AccessRequestService;
import swiss.trustbroker.api.idm.service.IdmService;
import swiss.trustbroker.api.profileselection.dto.ProfileSelectionData;
import swiss.trustbroker.api.profileselection.dto.ProfileSelectionResult;
import swiss.trustbroker.api.profileselection.service.ProfileSelectionService;
import swiss.trustbroker.api.qoa.service.QualityOfAuthenticationService;
import swiss.trustbroker.api.saml.dto.DestinationType;
import swiss.trustbroker.api.saml.dto.EncodingParameters;
import swiss.trustbroker.api.saml.service.OutputService;
import swiss.trustbroker.audit.service.AuditService;
import swiss.trustbroker.audit.service.InboundAuditMapper;
import swiss.trustbroker.audit.service.OutboundAuditMapper;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.dto.SamlBinding;
import swiss.trustbroker.common.saml.dto.SignatureContext;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.common.saml.util.EncryptionUtil;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.saml.util.SamlUtil;
import swiss.trustbroker.common.tracing.TraceSupport;
import swiss.trustbroker.common.util.ProcessUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.SsoSessionIdPolicy;
import swiss.trustbroker.federation.xmlconfig.AttributesSelection;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.Encryption;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.SloProtocol;
import swiss.trustbroker.homerealmdiscovery.dto.ProfileRequest;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.homerealmdiscovery.util.DefaultIdmStatusPolicyCallback;
import swiss.trustbroker.homerealmdiscovery.util.DefinitionUtil;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.saml.dto.ResponseData;
import swiss.trustbroker.saml.dto.ResponseParameters;
import swiss.trustbroker.saml.dto.ResponseStatus;
import swiss.trustbroker.saml.util.AssertionValidator;
import swiss.trustbroker.saml.util.ResponseFactory;
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
public class RelyingPartyService {

	@RequiredArgsConstructor(staticName = "of")
	private static class LogoutParams {

		final HttpServletRequest request;

		final HttpServletResponse response;

		final LogoutRequest logoutRequest;

		final String requestRelayState;

		final String requestReferrer;

		final SignatureContext signatureContext;

		final OutputService outputService;
	}

	private final StateCacheService stateCacheService;

	private final TrustBrokerProperties trustBrokerProperties;

	private final RelyingPartySetupService relyingPartySetupService;

	private final List<IdmService> idmServices;

	private final ProfileSelectionService profileSelectionService;

	private final SsoService ssoService;

	private final AuditService auditService;

	private final ScriptService scriptService;

	private final ApiSupport apiSupport;

	private final AccessRequestService accessRequestService;

	private final ResponseFactory responseFactory;

	private final UnknownUserPolicyService unknownUserPolicyService;

	private final QualityOfAuthenticationService qoaService;

	private void getAttributesFromIdm(CpResponse cpResponse, String requestIssuer, String requestReferer) {
		var idpIssuer = cpResponse.getIssuer();
		var relyingPartyConfig = RelyingParty.builder().id(requestIssuer).build();
		var callback = new DefaultIdmStatusPolicyCallback(cpResponse);

		for (var idmService : idmServices) {
			log.info("IDM call: issuer={} nameID={} requestIssuer={} requestReferer={}",
					idpIssuer, cpResponse.getNameId(), requestIssuer, requestReferer);

			var queryResponse = idmService.getAttributesFromIdm(relyingPartyConfig, cpResponse,
					cpResponse.getIdmLookup(), callback);
			if (queryResponse.isPresent()) {
				DefinitionUtil.mapCpAttributeList(queryResponse.get().getUserDetails(), cpResponse.getUserDetails());
				cpResponse.setOriginalUserDetailsCount(queryResponse.get().getOriginalUserDetailsCount());
				DefinitionUtil.mapCpAttributeList(queryResponse.get().getProperties(), cpResponse.getProperties());
				cpResponse.setOriginalPropertiesCount(queryResponse.get().getOriginalPropertiesCount());
			}
		}
	}

	public void setProperties(CpResponse cpResponse) {
		if (cpResponse.getIssuer() != null) {
			cpResponse.addPropertyIfMissing(CoreAttributeName.HOME_REALM.getName(),
					CoreAttributeName.HOME_REALM.getNamespaceUri(), cpResponse.getIssuer());
		}

		// If CP homeName is constant, or it was changes by the script(see RelyingPartySetupService.getHomeName), otherwise CP
		// attributes supporting OriginalIssuer wins
		var attribute = cpResponse.getAttribute(CoreAttributeName.HOME_NAME.getNamespaceUri());
		if (cpResponse.getHomeName() != null && !cpResponse.getHomeName().equals(attribute)) {
			cpResponse.addPropertyIfMissing(CoreAttributeName.HOME_NAME.getName(),
					CoreAttributeName.HOME_NAME.getNamespaceUri(), cpResponse.getHomeName());
		}

		var clientExtId = computeClientExtId(cpResponse);
		if (clientExtId != null) {
			cpResponse.addPropertyIfMissing(CoreAttributeName.ISSUED_CLIENT_EXT_ID.getName(),
					CoreAttributeName.ISSUED_CLIENT_EXT_ID.getNamespaceUri(), clientExtId);
		}

		var cpAuthLevel = relyingPartySetupService.getCpAuthLevel(cpResponse.getIssuer(), "");
		if (cpResponse.getAuthLevel() == null) {
			if (cpAuthLevel == null) {
				cpAuthLevel = qoaService.getUnspecifiedAuthLevel().getName();
			}
			cpResponse.setAuthLevel(cpAuthLevel);
			cpResponse.addPropertyIfMissing(CoreAttributeName.AUTH_LEVEL.getName(),
					CoreAttributeName.AUTH_LEVEL.getNamespaceUri(), cpAuthLevel);
		}

		var conversationId = TraceSupport.getOwnTraceParent();
		cpResponse.addPropertyIfMissing(CoreAttributeName.CONVERSATION_ID.getName(),
				CoreAttributeName.CONVERSATION_ID.getNamespaceUri(), conversationId);
	}

	static void adjustSsoSessionIdProperty(StateData stateData, CpResponse cpResponse) {
		if (stateData != null && stateData.getSsoSessionId() != null) {
			cpResponse.setProperty(CoreAttributeName.SSO_SESSION_ID.getName(),
					CoreAttributeName.SSO_SESSION_ID.getNamespaceUri(),
					stateData.getSsoSessionId());
		}
	}

	private String computeClientExtId(CpResponse cpResponse) {
		String clientExtId = cpResponse.getClientExtId();
		if (clientExtId != null) {
			return clientExtId;
		}
		Optional<String> queryClientExtId = relyingPartySetupService.getClientExtId(cpResponse.getIdmLookup());

		return queryClientExtId.orElse(null);
	}

	// Handling direct IDP response from CP with data from IDM
	public String sendResponseWithSamlResponseFromCp(OutputService outputService, ResponseData<Response> responseData,
			CpResponse cpResponse, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
		// state
		var idpRequestId = cpResponse.getInResponseTo();
		SamlValidationUtil.validateRelayState(responseData);
		var idpStateData = stateCacheService.find(responseData.getRelayState(), this.getClass().getSimpleName());
		log.debug("RP response SUCCESS forwarding from cpIssuer={} with idpRequestId={}",
				cpResponse.getIssuer(), idpRequestId);

		// bailout cases, update in case of SSO
		idpStateData.initiatedViaBinding(responseData.getBinding());

		// CP side auditing
		// To have a consistent conversationId we need the state but that one could have gone (we might lose the audit here)
		// on the other hand with INTERACTIVE profile selection we need to prevent auditing twice when /api/v1/hrd/profile is
		// called by the user selecting the wanted profile.
		auditResponseFromCp(httpServletRequest, responseData.getResponse(), cpResponse, idpStateData);

		// fetch data and have a first response with all data, profile selection follows
		fetchIdmData(cpResponse, idpStateData, cpResponse.getClientName());

		// block CP users not found in IDM
		unknownUserPolicyService.applyUnknownUserPolicy(cpResponse, getClaimsParty(cpResponse));

		// process CP response
		return sendSuccessSamlResponseToRp(outputService, responseData, cpResponse, idpStateData,
				httpServletRequest, httpServletResponse, null, idpStateData.getDeviceId());
	}

	// Handling all cases (direct CpResponse from CP or interactive profile selection from UI)
	@SuppressWarnings("java:S107")
	String sendSuccessSamlResponseToRp(OutputService outputService, ResponseData<Response> responseData, CpResponse cpResponse,
			StateData idpStateData, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
			String selectedProfileId, String incomingDeviceId) {

		// bailout in case script hook did an abort (SAML response with responder status, no profile selection etc.)
		if (cpResponse.isAborted()) {
			return sendFailedSamlResponseToRp(outputService, responseData, httpServletRequest, httpServletResponse, cpResponse);
		}

		// prepare session switch for SSO if needed, this one only makes sure we have the ssoSessionId in the response
		var relyingParty = getRelyingParty(idpStateData);

		// do initial profile selection if not yet decided already by user
		if (selectedProfileId == null) {
			var profileSelectionData = ProfileSelectionData.builder()
					.profileSelectionProperties(relyingParty.getProfileSelection())
					.selectedProfileId(selectedProfileId)
					.exchangeId(responseData.getRelayState())
					.oidcClientId(idpStateData.getRpOidcClientId())
					.build();
			var psResult = profileSelectionService.doInitialProfileSelection(
					profileSelectionData, relyingParty, cpResponse, idpStateData);
			updateAttributes(psResult, cpResponse);
			if (psResult.getRedirectUrl() != null) {
				// we need to remember CpResponse here, so we can continue after the user has selected account/profile
				updateStateWithCpResponse(cpResponse, idpStateData);
				return psResult.getRedirectUrl();
			}
		}

		// save final IDP response state for AR or SSO
		idpStateData.setCpResponse(cpResponse);
		var arRedirect = performAccessRequestIfRequired(httpServletRequest, relyingParty, idpStateData, null);
		if (arRedirect != null) {
			return arRedirect;
		}

		// Return from SSO step-up
		var claimsParty = getClaimsParty(cpResponse);
		var subjectNameId = cpResponse.getNameId();
		var stateByCookieId = ssoService.findValidStateFromCookies(
				relyingParty, claimsParty, subjectNameId, httpServletRequest.getCookies());
		var stateDataForResponse = stateByCookieId.orElse(null);
		if (stateDataForResponse != null) {
			log.debug("Session state={} found based on cookie, checking SSO for incomingDeviceId={}",
					stateDataForResponse.getId(), incomingDeviceId);
			if (ssoService.ssoStateValidForDeviceInfo(claimsParty, relyingParty, stateDataForResponse, idpStateData,
					incomingDeviceId, claimsParty.getId())) {
				ssoService.completeDeviceInfoPreservingStateForSso(stateDataForResponse, idpStateData, relyingParty);
				log.info("Joined SSO sessionId={} for authnSessionId={}", stateDataForResponse.getId(), idpStateData.getId());
			}
			else {
				log.info("Cannot join SSO sessionId={} for authnSessionId={} caused by failed CP post-condition"
								+ " from cpIssuer={} providing cpCtx='{}' where rpIssuer={} requested rpCtx='{}'",
						stateDataForResponse.getId(), idpStateData.getId(),
						cpResponse.getIssuer(), cpResponse.getContextClasses(),
						idpStateData.getRpIssuer(), idpStateData.getRpContextClasses());
				stateDataForResponse = idpStateData;
			}
		}
		else {
			log.debug("No SSO state found for rpIssuerId={} cpIssuerId={} subjectNameId={}",
					relyingParty.getId(), claimsParty.getId(), subjectNameId);
		}

		// SSO session switch or non-SSO session discard after everything was done
		if (stateDataForResponse == null) {
			stateDataForResponse = idpStateData;
			adjustSsoSessionIdForRpResponse(relyingParty, idpStateData, cpResponse);
			establishSsoOrInvalidateState(relyingParty, idpStateData, true);
		}
		else {
			invalidateStateData(idpStateData, true);
		}

		// send
		var encodingParameters = buildEncodingParameters(relyingParty, stateDataForResponse, responseData.getBinding());
		var samlResponse = createSignedSamlResponse(cpResponse, stateDataForResponse);
		var resultResponseData = ResponseData.of(samlResponse, null, null);
		sendResponseToRp(resultResponseData, cpResponse, Optional.of(stateDataForResponse), httpServletRequest,
				httpServletResponse, encodingParameters, outputService);
		return null;
	}

	private static void updateAttributes(ProfileSelectionResult psResult, CpResponse cpResponse) {
		var filteredAttributes = psResult.getFilteredAttributes();
		if (filteredAttributes.isPresent()) {
			cpResponse.setUserDetails(DefinitionUtil.mapCpAttributeList(filteredAttributes.get()));
		}
	}

	public String performAccessRequestIfRequired(HttpServletRequest httpServletRequest,
			RelyingParty relyingParty, StateData idpStateData, StateData stateDataByAuthnReq) {
		// check freshness of data within the one session we have - need to have the right tenant for the check
		refreshUserDataIfNeeded(idpStateData, stateDataByAuthnReq, relyingParty);
		if (HrdSupport.requestFromTestApplication(httpServletRequest)) {
			// no access request for automated tests (OIDC and SAML)
			log.info("Skipping access request check for call from test application");
			return null;
		}
		var httpData = AccessRequestHttpData.of(httpServletRequest);
		var arResult = accessRequestService.performAccessRequestIfRequired(httpData, relyingParty, idpStateData,
				() -> fetchIdmData(idpStateData.getCpResponse(), idpStateData, relyingParty.getClientName()));
		// initiate AR to maybe create new data in IDM
		if (arResult.getRedirectUrl() != null) {
			stateCacheService.save(idpStateData, this.getClass().getSimpleName());
			return arResult.getRedirectUrl();
		}
		// continue with normal result, but keep session
		if (arResult.isRetainSession()) {
			ssoService.establishImplicitSso(relyingParty, idpStateData);
		}
		return null;
	}

	// provide either StateData with original InitiatedViaArtifactBinding stored in spStateData, or binding from current request
	static boolean useArtifactBinding(RelyingParty relyingParty, StateData stateData, SamlBinding binding) {
		var trigger = "inbound_binding";
		var initiatedViaArtifactBinding = binding == SamlBinding.ARTIFACT;
		if (!initiatedViaArtifactBinding && stateData != null) {
			trigger = "session_rp_binding";
			initiatedViaArtifactBinding = Boolean.TRUE.equals(stateData.getSpStateData().getInitiatedViaArtifactBinding());
			if (!initiatedViaArtifactBinding) {
				trigger = "session_cp_binding";
				initiatedViaArtifactBinding = Boolean.TRUE.equals(stateData.getInitiatedViaArtifactBinding());
			}
		}
		var useArtifactBinding = relyingParty.getSamlArtifactBinding() != null &&
				relyingParty.getSamlArtifactBinding().useArtifactBinding(initiatedViaArtifactBinding);
		if (useArtifactBinding) {
			log.debug(
					"Use artifact binding for response with rpIssuerId={} artifactBinding={} initiatedViaArtifactBinding={} "
							+ "artifactBindingTrigger={}",
					relyingParty.getId(), relyingParty.getSamlArtifactBinding(), initiatedViaArtifactBinding, trigger);
		}
		return useArtifactBinding;
	}

	private void updateStateWithCpResponse(CpResponse cpResponse, StateData stateData) {
		stateData.setCpResponse(cpResponse);
		stateCacheService.save(stateData, this.getClass().getSimpleName());
	}

	private void updateCpResponseForSso(CpResponse cpResponse, StateData spStateData, String clientName) {
		// remove old attributes
		cpResponse.getUserDetails().clear();
		cpResponse.getProperties().clear();

		// IDM data
		var requestIssuer = spStateData.getIssuer();
		var requestReferer = spStateData.getReferer();

		// reset original attribute list
		var notProcessedAttributes = cpResponse.getOriginalAttributes();
		if (notProcessedAttributes != null) {
			cpResponse.setAttributes(new HashMap<>(notProcessedAttributes));
		}

		String acsUrl = spStateData.getAssertionConsumerServiceUrl();
		String destination = acsUrl != null ? acsUrl : requestReferer;
		if (destination != null) {
			cpResponse.setRpDestination(destination);
		}

		cpResponse.setClientName(clientName);
		cpResponse.setRpIssuer(requestIssuer);
		cpResponse.setRpContext(spStateData.getRpContext());

		scriptService.processCpBeforeIdm(cpResponse, null, cpResponse.getIssuer(), requestReferer);

		// filter CP attributes
		var cpAttributeDefinitions = relyingPartySetupService.getCpAttributeDefinitions(cpResponse.getIssuer(), "");
		if (!cpAttributeDefinitions.isEmpty()) {
			ResponseFactory.filterCpAttributes(cpResponse, cpAttributeDefinitions);
		}

		var idmLookUp = relyingPartySetupService.getIdmLookUp(requestIssuer, requestReferer);
		idmLookUp.ifPresent(idmLookup -> cpResponse.setIdmLookup(idmLookup.shallowClone()));

		// set clientExtId
		cpResponse.setClientExtId(relyingPartySetupService.getRpClientExtId(requestIssuer, requestReferer));

		// scripts BeforeIdm RP side (see test DeriveClaimProviderNameFromNameIdFormat.groovy for an example to derive HomeName)
		scriptService.processRpBeforeIdm(cpResponse, null, requestIssuer, requestReferer);
	}

	public void filterPropertiesSelection(CpResponse cpResponse, String requestIssuer, String requestReferer) {
		AttributesSelection propertiesAttrSelection =
				relyingPartySetupService.getPropertiesAttrSelection(requestIssuer, requestReferer);
		Map<Definition, List<String>> filteredProperties = cpResponse.getProperties().entrySet().stream()
				.filter(map -> attributeMustBeInResponse(map.getKey(), propertiesAttrSelection))
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

		cpResponse.setProperties(filteredProperties);
	}

	private static boolean attributeMustBeInResponse(Definition attributeDefinition,
			AttributesSelection propertiesAttrSelection) {
		if (propertiesAttrSelection == null || propertiesAttrSelection.getDefinitions() == null) {
			return false;
		}
		List<Definition> definitions = propertiesAttrSelection.getDefinitions();
		for (Definition definition : definitions) {
			if (attributeDefinition.equalsByNameAndNamespace(definition)) {
				return true;
			}
		}
		return false;
	}

	public String sendFailedSamlResponseToRp(
			OutputService outputService, ResponseData<Response> responseData, HttpServletRequest httpServletRequest,
			HttpServletResponse httpServletResponse, CpResponse cpResponse) {
		var idpRequestId = cpResponse.getInResponseTo();
		SamlValidationUtil.validateRelayState(responseData);
		var idpStateData = stateCacheService.find(responseData.getRelayState(), this.getClass().getSimpleName());
		log.debug("RP response FAILED forwarding from cpIssuer={} with idpRequestId={}",
				cpResponse.getIssuer(), idpRequestId);

		// bailout cases, update in case of SSO
		idpStateData.initiatedViaBinding(responseData.getBinding());

		// handle an error display with continue to RP
		if (cpResponse.isAborted() && cpResponse.showErrorPage()) {
			// we need to remember CpResponse here
			updateStateWithCpResponse(cpResponse, idpStateData);
			return apiSupport.getErrorPageUrlWithFlags(cpResponse.uiErrorCode(),
					TraceSupport.getOwnTraceParent(), idpStateData.getId(), cpResponse.uiFlags());
		}

		// audit incoming (to have a consistent conversationId we need the state, if gone we loose the correlation)
		auditResponseFromCp(httpServletRequest, responseData.getResponse(), cpResponse, idpStateData);

		// clone status from original response (a SAML object cannot be assigned to another parent)
		var authnResponse = createSamlResponseFromState(idpStateData, cpResponse);
		SamlValidationUtil.validateResponse(responseData);

		if (cpResponse.isAborted()) {
			setAbortedResponseStatus(cpResponse, authnResponse);
		}
		else {
			// propagated or overwritten status
			var response = responseData.getResponse();
			var statusMessage = OpenSamlUtil.getStatusMessage(response);
			var statusCode = OpenSamlUtil.getStatusCode(response);
			var nestedStatus = OpenSamlUtil.getNestedStatusCode(response);
			authnResponse.setStatus(SamlFactory.createResponseStatus(statusCode, statusMessage, nestedStatus));
		}

		// sign message
		var relyingParty = getRelyingParty(idpStateData);
		prepareResponseToRp(authnResponse,
				relyingParty,
				trustBrokerProperties.getSkinnyAssertionNamespaces(),
				signFailureResponse(relyingParty));

		// send and audit
		establishSsoOrInvalidateState(relyingParty, idpStateData, false);
		var encodingParameters = buildEncodingParameters(relyingParty, idpStateData, responseData.getBinding());
		var resultResponseData = ResponseData.of(authnResponse, null, null);
		sendResponseToRp(resultResponseData, cpResponse, Optional.of(idpStateData),
				httpServletRequest, httpServletResponse, encodingParameters, outputService);

		return null; // no redirects
	}

	public String sendAbortedSamlResponseToRp(
			OutputService outputService, StateData stateData, HttpServletRequest httpServletRequest,
			HttpServletResponse httpServletResponse, ResponseStatus responseStatus,
			SamlBinding samlBinding) {
		// responder directly triggering on AuthnRequest
		var authnResponse = createSamlResponseFromState(stateData, null);
		setAbortedResponseStatus(responseStatus, authnResponse);

		// sign message
		var relyingParty = getRelyingParty(stateData);
		prepareResponseToRp(authnResponse,
				relyingParty,
				trustBrokerProperties.getSkinnyAssertionNamespaces(),
				signFailureResponse(relyingParty));

		// send and audit
		invalidateStateData(stateData, false);
		var encodingParameters = buildEncodingParameters(relyingParty, stateData, samlBinding);
		var resultResponseData = ResponseData.of(authnResponse, null, null);
		sendResponseToRp(resultResponseData, null, Optional.of(stateData),
				httpServletRequest, httpServletResponse, encodingParameters, outputService);

		return null; // no redirects
	}

	private void setAbortedResponseStatus(ResponseStatus responseStatus, Response authnResponse) {
		// script hook has overwritten the status
		var statusCode = responseStatus.getStatusCode();
		var nestedStatusCode = responseStatus.nestedStatusCode(trustBrokerProperties.getSaml());
		var statusMessage = responseStatus.statusMessage(trustBrokerProperties.getSaml());
		if (log.isDebugEnabled()) {
			log.debug("SAML exchange aborted by scripts signaling statusCode={} statusNestedCode={} statusMessage='{}'",
					statusCode, nestedStatusCode, statusMessage);
		}
		authnResponse.setStatus(SamlFactory.createResponseStatus(statusCode, statusMessage, nestedStatusCode));
	}

	private static void prepareResponseToRp(StatusResponseType response,
			RelyingParty relyingParty,
			String skinnyAssertionNamespaces,
			boolean sign) {
		if (sign) {
			log.debug("Sending signed SAML response id={} towards RP rpIssuerId={}", response.getID(), relyingParty.getId());
			var signatureParameters = relyingParty.getSignatureParametersBuilder()
					.skinnyAssertionNamespaces(skinnyAssertionNamespaces)
					.build();
			SamlFactory.signSignableObject(response, signatureParameters);
		}
		else {
			log.info("Sending unsigned SAML response id={} towards RP rpIssuerId={}", response.getID(), relyingParty.getId());
			var signatureAlgos = relyingParty.getSignature();
			SamlUtil.prepareSamlObject(response,
					signatureAlgos != null ? signatureAlgos.getCanonicalizationAlgorithm() : null,
					null,
					skinnyAssertionNamespaces);
		}
	}

	private void sendResponseToRp(ResponseData<?> responseData, CpResponse cpResponse,
			Optional<StateData> idpStateData, HttpServletRequest httpServletRequest,
			HttpServletResponse httpServletResponse, EncodingParameters encodingParameters, OutputService outputService) {
		addSsoCookies(idpStateData, httpServletResponse);
		sendResponse(responseData, cpResponse, idpStateData, httpServletRequest, httpServletResponse,
				encodingParameters, outputService);
	}

	private void addSsoCookies(Optional<StateData> idpStateData, HttpServletResponse httpServletResponse) {
		if (idpStateData.isPresent()) {
			var stateData = idpStateData.get();
			if (stateData.isSsoEstablished()) {
				// SSO cookie for established session
				var cookie = ssoService.generateCookie(stateData);
				httpServletResponse.addCookie(cookie);
			}
		}
	}

	private void sendResponse(ResponseData<?> responseData, CpResponse cpResponse,
			Optional<StateData> idpStateData, HttpServletRequest httpServletRequest,
			HttpServletResponse httpServletResponse, EncodingParameters encodingParameters, OutputService outputService) {
		// wrap response and handle relay state
		var response = responseData.getResponse();
		var destinationUrl = getDestination(response, idpStateData, cpResponse);
		var relayState = getRelayState(idpStateData, responseData.getRelayState());

		// emit
		outputService.sendResponse(response, null, relayState, destinationUrl, httpServletResponse,
				encodingParameters, DestinationType.RP);

		// audit
		if (response instanceof Response) {
			auditResponseToRp(httpServletRequest, response, cpResponse, idpStateData.orElse(null));
		}

		txDelay();
	}

	// testing only
	private void txDelay() {
		var txDelay = trustBrokerProperties.getStateCache() == null ? 0 :
				trustBrokerProperties.getStateCache().getTxCommitDelay();
		if (txDelay > 0) {
			log.error("Delaying stateCache TX commit for {}ms to test race-conditions", txDelay);
			ProcessUtil.sleep(txDelay);
		}
	}

	private static String getRelayState(Optional<StateData> idpStateData, String requestRelayState) {
		var relayState = requestRelayState;
		if (relayState == null && idpStateData.isPresent()) {
			relayState = idpStateData.get().getSpStateData().getRelayState();
		}
		return relayState;
	}

	private boolean isRelyingPartyOkForSso(RelyingParty relyingParty, StateData idpStateData) {
		return relyingParty.isSsoEnabled() && ssoService.allowSso(idpStateData);
	}

	// pre-establish SSO before message generation
	private void adjustSsoSessionIdForRpResponse(RelyingParty relyingParty, StateData idpStateData, CpResponse cpResponse) {
		if (isRelyingPartyOkForSso(relyingParty, idpStateData)) {
			idpStateData.setSsoSessionId(SsoSessionIdPolicy.generateSsoId(true, trustBrokerProperties.getSsoSessionIdPolicy()));
			adjustSsoSessionIdProperty(idpStateData, cpResponse);
		}
	}

	// post-establish SSO after message generation
	private void establishSsoOrInvalidateState(RelyingParty relyingParty, StateData idpStateData, boolean success) {
		if (success && isRelyingPartyOkForSso(relyingParty, idpStateData)) {
			var ssoGroupName = relyingParty.getSso().getGroupName();
			var ssoGroup = relyingPartySetupService.getSsoGroupConfig(ssoGroupName);
			ssoService.establishSso(relyingParty, idpStateData, ssoGroup);
		}
		invalidateStateData(idpStateData, success);
	}

	private void invalidateStateData(StateData idpStateData, boolean success) {
		if (!idpStateData.isSsoEstablished()) {
			stateCacheService.invalidate(idpStateData, success, this.getClass().getSimpleName());
		}
	}

	private RelyingParty getRelyingParty(StateData idpStateData) {
		var requestIssuer = idpStateData.getRpIssuer();
		var requestReferer = idpStateData.getRpReferer();
		return relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(requestIssuer, requestReferer);
	}

	private ClaimsParty getClaimsParty(CpResponse cpResponse) {
		var cpIssuerId = cpResponse.getIssuer();
		return relyingPartySetupService.getClaimsProviderSetupByIssuerId(cpIssuerId, null);
	}

	// if stateDataByAuthnReq is null, relyingParty.id is used for the check, stateDataByAuthnReq is assumed to match
	// relyingParty
	private void refreshUserDataIfNeeded(StateData ssoStateData, StateData stateDataByAuthnReq, RelyingParty relyingParty) {
		var cpResponse = ssoStateData.getCpResponse();
		var authnIssuerId = stateDataByAuthnReq != null ? stateDataByAuthnReq.getRpIssuer() :
				relyingParty.getId();
		// if tenant matches we can continue with the state data
		// NOTE: We could do a freshness check here in case the state data is older than X because of changes in IDM => LATER
		if (authnIssuerId.equals(cpResponse.getRpIssuer()) &&
				!(relyingParty.isSsoEnabled() && Boolean.TRUE.equals(relyingParty.getSso().getForceIdmRefresh()))) {
			log.info("Skip refreshing user data because IDP response already based on clientTenant={} for rpId={} "
					+ "(without SSO or forceIdmRefresh=true)", cpResponse.getRpIssuer(), relyingParty.getId());
			return;
		}
		// update with tenant data of the joining SSO member
		log.debug("Refreshing user data as authenticating issuer rpIssuerId={} is not IDP response clientTenant={} rpId={}",
				authnIssuerId, cpResponse.getRpIssuer(), relyingParty.getId());
		var stateToUpdate = stateDataByAuthnReq != null ? stateDataByAuthnReq : ssoStateData;
		fetchIdmData(cpResponse, stateToUpdate, relyingParty.getClientName());
		if (stateDataByAuthnReq != null) {
			stateDataByAuthnReq.setCpResponse(cpResponse);
		}
	}

	public String sendAuthnResponseToRpFromState(OutputService outputService, HttpServletRequest httpServletRequest,
			HttpServletResponse httpServletResponse, StateData ssoStateData,
			StateData stateDataByAuthnReq) {

		// accept input
		var cpResponse = ssoStateData.getCpResponse();
		var authnRequestID = stateDataByAuthnReq.getSpStateData().getId();
		SamlUtil.validateSessionId(authnRequestID, "AuthnRequestId used as SP state ID");

		// keep operating on stateDataByAuthnReq until profile selection has been decided
		var spIssuer = stateDataByAuthnReq.getRpIssuer();
		var relyingParty = relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(spIssuer, null);

		// in any case we need the data related to the RP tenant calling us
		log.debug("Done SSO all-profiles for cpIssuer={} rpIssuer={} subjectNameId={} authnRequestID={}",
				cpResponse.getIssuer(), relyingParty.getId(), cpResponse.getNameId(), authnRequestID);
		refreshUserDataIfNeeded(ssoStateData, stateDataByAuthnReq, relyingParty);

		// handle multiple profiles if feature is enabled
		var profileSelectionData = ProfileSelectionData.builder()
		   		.profileSelectionProperties(relyingParty.getProfileSelection())
				.selectedProfileId(ssoStateData.getSelectedProfileExtId())
				.exchangeId(stateDataByAuthnReq.getSpStateData().getRelayState())
				.oidcClientId(stateDataByAuthnReq.getRpOidcClientId())
				.build();
		var psResult = profileSelectionService.doSsoProfileSelection(
				profileSelectionData, relyingParty, cpResponse, stateDataByAuthnReq);
		if (psResult.getSelectedProfileId() != null) {
			stateDataByAuthnReq.setSelectedProfileExtId(psResult.getSelectedProfileId());
		}
		updateAttributes(psResult, cpResponse);
		if (psResult.getRedirectUrl() != null) {
			updateStateWithCpResponse(cpResponse, stateDataByAuthnReq);
			return psResult.getRedirectUrl();
		}

		// ready to join SSO session
		ssoService.completeDeviceInfoPreservingStateForSso(ssoStateData, stateDataByAuthnReq, relyingParty);

		// send out audited response
		var authnResponse = createSignedSamlResponse(cpResponse, ssoStateData);
		var encodingParameters = buildEncodingParameters(relyingParty, ssoStateData, null);
		var responseData = ResponseData.of(authnResponse, null, null);
		sendResponse(responseData, cpResponse, Optional.of(ssoStateData), httpServletRequest, httpServletResponse,
				encodingParameters, outputService);

		return null;
	}

	// internal, tested

	private void fetchIdmData(CpResponse cpResponse, StateData stateData, String clientName) {
		log.debug("Fetch IDM data for stateData={} cpResponse.issuer='{}' cpResponse.rpIssuer='{}' clientName='{}'",
				stateData.getId(), cpResponse.getIssuer(), cpResponse.getRpIssuer(), clientName);

		var spStateData = stateData.getSpStateData();

		// IDM data
		var requestIssuer = spStateData.getIssuer();
		var requestReferer = spStateData.getReferer();

		// make sure CpResponse is clean for reuse
		updateCpResponseForSso(cpResponse, spStateData, clientName);

		// retrieve current attributes from IDM services
		getAttributesFromIdm(cpResponse, requestIssuer, requestReferer);

		// derived attributes
		setProperties(cpResponse);

		// scripts (just before signing)
		scriptService.processRpAfterIdm(cpResponse, null, requestIssuer, requestReferer);

		// filter properties
		var alreadySelectedProfile = stateData.getSelectedProfileExtId();
		if (alreadySelectedProfile != null) {
			var relyingParty = getRelyingParty(stateData);
			var profileSelectionData = ProfileSelectionData.builder()
				   .profileSelectionProperties(relyingParty.getProfileSelection())
				   .selectedProfileId(alreadySelectedProfile)
				   .enforceSingleProfile(false)
				   .exchangeId(stateData.getSpStateData().getRelayState())
				   .oidcClientId(stateData.getRpOidcClientId())
				   .build();
			var psResult = profileSelectionService.doFinalProfileSelection(profileSelectionData, relyingParty, cpResponse,
					stateData);
			updateAttributes(psResult, cpResponse);
		}
		else {
			filterPropertiesSelection(cpResponse, requestIssuer, requestReferer);
		}
	}

	private Response createSignedSamlResponse(CpResponse cpResponse, StateData stateData) {
		var spStateData = stateData.getSpStateData();
		var requestIssuer = spStateData.getIssuer();
		var requestReferer = spStateData.getReferer();
		var relyingParty = getRelyingParty(stateData);

		// adjust final settings
		adjustSsoSessionIdProperty(stateData, cpResponse);
		SubjectNameMapper.adjustSubjectNameId(cpResponse, relyingParty);
		processOnResponseScript(cpResponse, requestIssuer, requestReferer);

		// assemble and sign
		var authnResponse = createSamlResponseFromState(stateData, cpResponse);

		// pass it on
		if (cpResponse.isAborted()) {
			setAbortedResponseStatus(cpResponse, authnResponse);
		}
		else {
			authnResponse.setStatus(SamlFactory.createResponseStatus(StatusCode.SUCCESS));

			List<String> dropDuplicatedAttributes = Collections.emptyList();
			var dropDuplicatedAttributesConfig = trustBrokerProperties.getOidc().getDropDuplicatedAttributeFromOriginalIssuer();
			if (isXtbDestination(authnResponse.getDestination()) && ArrayUtils.isNotEmpty(dropDuplicatedAttributesConfig)) {
				dropDuplicatedAttributes = Arrays.asList(dropDuplicatedAttributesConfig);
				log.debug("OIDC: Dropping original issuer version if duplicated for attributes={}", dropDuplicatedAttributes);
			}
			var responseParameters = ResponseParameters.builder()
													   .rpIssuerId(requestIssuer)
													   .rpReferer(requestReferer)
													   .dropDuplicatedAttributeFromOriginalIssuer(dropDuplicatedAttributes)
													   .build();
			var assertion = responseFactory.createAssertion(stateData, cpResponse, responseParameters);

			// encrypt assertion (if necessary)
			setAssertion(authnResponse, assertion, relyingParty);
		}

		// sign message as well
		prepareResponseToRp(authnResponse, relyingParty,
				trustBrokerProperties.getSkinnyAssertionNamespaces(),
				signSuccessResponse(relyingParty));
		return authnResponse;
	}

	private void processOnResponseScript(CpResponse cpResponse, String requestIssuer, String requestReferer) {
		if (cpResponse != null) {
			scriptService.processOnResponse(cpResponse, null, requestIssuer, requestReferer);
		}
	}

	boolean signSuccessResponse(RelyingParty relyingParty) {
		return relyingParty.requireSignedResponse(trustBrokerProperties.getSecurity().isDoSignSuccessResponse());
	}

	boolean signFailureResponse(RelyingParty relyingParty) {
		return relyingParty.requireSignedResponse(trustBrokerProperties.getSecurity().isDoSignFailureResponse());
	}

	public void setAssertion(Response authnResponse, Assertion assertion, RelyingParty relyingParty) {
		var rpId = relyingParty.getId();

		Encryption encryption = relyingParty.getEncryption();
		var kea = getKeyEncryptionAlgorithm(encryption);
		var dea = getDataEncryptionAlgorithm(encryption);

		Credential encryptionCred = relyingParty.getEncryptionCred();

		// If destination is XTB -> encryption for OIDC
		boolean isXtbDestination = isXtbDestination(authnResponse.getDestination());
		if (isXtbDestination) {
			encryptionCred = relyingParty.getRpSigner();
		}

		if (assertionEncryptionReq(encryptionCred, isXtbDestination, rpId)) {
			Encrypter.KeyPlacement keyPlacement = getKeyPlacement(encryption, rpId);
			EncryptedAssertion encryptedAssertion = EncryptionUtil.encryptAssertion(assertion,
					encryptionCred, dea, kea, keyPlacement, rpId);
			authnResponse.getEncryptedAssertions().add(encryptedAssertion);
			log.debug("Assertion for rp={} encrypted with cred={}, DataEncryptionAlg={} KeyEncryptionAlg={}", rpId,
					encryptionCred.getEntityId(), dea, kea);
			return;
		}

		authnResponse.getAssertions().add(assertion);
	}

	private boolean isXtbDestination(String destination) {
		try {
			URI destinationUrl = new URI(destination);
			URI oidcPerimeterUrl = new URI(trustBrokerProperties.getOidc().getPerimeterUrl());
			if (destinationUrl.getHost() == null || oidcPerimeterUrl.getHost() == null) {
				return false;
			}
			return destinationUrl.getHost().equals(oidcPerimeterUrl.getHost());
		}
		catch (URISyntaxException ex) {
			throw new RequestDeniedException("Invalid URL", ex);
		}
	}

	boolean assertionEncryptionReq(Credential encryptionCred, boolean isXtbDestination, String rpId) {

		if (encryptionCred == null) {
			log.debug("No EncryptionKeystore on={}, assertion encryption will be skipped", rpId);
			return false;
		}

		if (isXtbDestination) {
			boolean samlEncrypt = trustBrokerProperties.getOidc().isSamlEncrypt();
			log.debug("Encrypt Assertion for OIDC id={} enabled={}", rpId, samlEncrypt);
			return samlEncrypt;
		}

		return true;
	}


	public static String getDataEncryptionAlgorithm(Encryption encryption) {
		if (encryption == null || encryption.getDataEncryptionAlgorithm() == null) {
			return EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256;
		}
		return encryption.getDataEncryptionAlgorithm();
	}

	public static String getKeyEncryptionAlgorithm(Encryption encryption) {
		if (encryption == null || encryption.getKeyEncryptionAlgorithm() == null) {
			return EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP;
		}
		return encryption.getKeyEncryptionAlgorithm();
	}

	private static Encrypter.KeyPlacement getKeyPlacement(Encryption encryption, String requestIssuer) {
		if (encryptionHasValidKeyPlacement(encryption)) {
			return Encrypter.KeyPlacement.valueOf(encryption.getKeyPlacement());
		}
		log.debug("Missing KeyPlacement config for={}, falling back to PEER", requestIssuer);
		return Encrypter.KeyPlacement.PEER;
	}

	private static boolean encryptionHasValidKeyPlacement(Encryption encryption) {
		if (encryption == null || encryption.getKeyPlacement() == null) {
			return false;
		}
		return encryption.getKeyPlacement().equals(Encrypter.KeyPlacement.PEER.name()) ||
				encryption.getKeyPlacement().equals(Encrypter.KeyPlacement.INLINE.name());
	}

	public void handleLogoutRequest(OutputService outputService, LogoutRequest logoutRequest, String requestRelayState,
			HttpServletRequest request, HttpServletResponse response, SignatureContext signatureContext) {
		var issuer = logoutRequest.getIssuer().getValue();
		var requestReferrer = WebUtil.getHeader(HttpHeaders.REFERER, request);
		var relyingParties = ssoService.getRelyingPartiesForSamlSlo(issuer, requestReferrer);
		validateLogoutRequest(logoutRequest, signatureContext, relyingParties);
		var logoutParams = LogoutParams.of(request, response, logoutRequest, requestRelayState, requestReferrer,
				signatureContext, outputService);
		var logoutState = SsoService.SloState.builder().build();
		for (var relyingParty : relyingParties) {
			logoutRelyingParty(relyingParty, requestReferrer, logoutParams, logoutState);
		}
	}

	private void logoutRelyingParty(RelyingParty relyingParty, String referer, LogoutParams logoutParams,
			SsoService.SloState sloState) {
		var stateData = ssoService.logoutRelyingParty(logoutParams.logoutRequest.getIssuer().getValue(),
				mapSessionIndexes(logoutParams.logoutRequest.getSessionIndexes()),
				relyingParty, logoutParams.request.getCookies(), sloState);

		// we audit for every cookie we kill
		ssoService.auditLogoutRequestFromRp(
				logoutParams.request, logoutParams.logoutRequest, stateData.orElse(null), relyingParty, null);

		// we send a SAML POST LogoutResponse only once
		// referrer matches are processed first, hence we send the response based on the referrer if we find a match for that
		if (!sloState.isResponseSent()) {
			var encodingParameters = buildEncodingParameters(relyingParty, null, logoutParams.signatureContext.getBinding());
			WebUtil.addCookies(logoutParams.response, sloState.getCookiesToExpire());

			sendLogoutResponse(logoutParams, sloState, stateData, relyingParty,
					referer, encodingParameters);
			sloState.setResponseSent(true);
		}
	}

	@SuppressWarnings("java:S1168")
	private static List<String> mapSessionIndexes(List<SessionIndex> sessionIndices) {
		if (sessionIndices == null) {
			return null;
		}
		return sessionIndices.stream().map(SessionIndex::getValue).toList();
	}

	private void validateLogoutRequest(LogoutRequest logoutRequest, SignatureContext signatureContext,
			List<RelyingParty> relyingParties) {
		if (!relyingParties.isEmpty()) {
			// The check is based on the first RP (based on the issuer, if found), we use that one for the LogoutResponse
			// This check needs to be performed before sending the response in the loop.
			// use the same flags as for AuthnRequest to control if request and signature validation is required or optional
			if (trustBrokerProperties.getSecurity().isValidateAuthnRequest()) {
				// use the RP to which we send the LogoutResponse below - SLO matches referrer before issuer
				var signingRp = relyingParties.get(0);
				log.debug("Relying party for LogoutRequest signature verification is id={}", signingRp.getId());
				validateBinding(signingRp, signatureContext.getBinding());
				signatureContext.setRequireSignature(signingRp.requireSignedAuthnRequest());
				AssertionValidator.validateRequestSignature(logoutRequest, signingRp.getRpTrustCredentials(),
						trustBrokerProperties,
						signatureContext);
			}
			else {
				log.error("trustbroker.config.security.validateAuthnRequest=false: Security on LogoutRequest disabled!!!");
			}
		}
	}

	private static void validateBinding(RelyingParty relyingParty, SamlBinding binding) {
		if (!relyingParty.isValidInboundBinding(binding)) {
			throw new RequestDeniedException(String.format("Relying party rpIssuerId=%s does not support inbound binding=%s",
					relyingParty.getId(), binding));
		}
	}

	private void sendLogoutResponse(LogoutParams logoutParams, SsoService.SloState sloState, Optional<StateData> stateData,
			RelyingParty relyingParty, String referer, EncodingParameters encodingParameters) {
		var sloUrl = ssoService.computeSamlSingleLogoutUrl(logoutParams.requestReferrer, relyingParty);
		var issuer = relyingParty.getSloIssuer(SloProtocol.SAML2).orElse(null);
		var logoutResponse = createLogoutResponse(logoutParams.logoutRequest, sloUrl, issuer);
		logoutResponse.setStatus(SamlFactory.createResponseStatus(StatusCode.SUCCESS));
		// sign message as well
		prepareResponseToRp(logoutResponse, relyingParty,
				trustBrokerProperties.getSkinnyAssertionNamespaces(),
				signSuccessResponse(relyingParty));
		// NameID for SAML notifications
		NameID nameId = getNameIdFromSessionOrLogoutRequest(stateData, logoutParams.logoutRequest);
		var params = ssoService.buildSloVelocityParameters(relyingParty, referer, sloState.getSloNotifications(), nameId,
				null, null);
		encodingParameters.setTemplateParameters(params);
		var responseData = ResponseData.of(logoutResponse, logoutParams.requestRelayState, null);
		sendResponseToRp(responseData, null, stateData, logoutParams.request, logoutParams.response,
				encodingParameters, logoutParams.outputService);
	}

	private static NameID getNameIdFromSessionOrLogoutRequest(Optional<StateData> stateData, LogoutRequest logoutRequest) {
		NameID nameId = null;
		if (stateData.isPresent()) {
			nameId = ResponseFactory.createNameId(stateData.get().getCpResponse());
			if (nameId != null) {
				log.debug("SLO notification NameId={} from session with id={}", nameId, stateData.get().getId());
			}
		}
		if (nameId == null) {
			nameId = logoutRequest.getNameID();
			log.info("No session, using SLO notification nameId={} from LogoutRequest with id={}",
					nameId != null ? nameId.getValue() : "", logoutRequest.getID());
			// this way an attacker could trigger a logout for someone else (with an unsigned LogoutRequest)
			// as the logout should only affect state associated with the requesting browser, this is not a problem
		}
		return nameId;
	}

	private static EncodingParameters buildEncodingParameters(RelyingParty relyingParty, StateData idpStateData,
			SamlBinding inboundSamlBinding) {
		var useArtifactBinding = useArtifactBinding(relyingParty, idpStateData, inboundSamlBinding);
		return EncodingParameters.builder().useArtifactBinding(useArtifactBinding).build();
	}

	private Response createSamlResponseFromState(StateData idpStateData, CpResponse cpResponse) {
		var response = SamlFactory.createResponse(Response.class, trustBrokerProperties.getIssuer());
		response.setDestination(ResponseFactory.getRpDestination(idpStateData, cpResponse));
		response.setInResponseTo(idpStateData.getSpStateData().getId());
		return response;
	}

	private StatusResponseType createLogoutResponse(LogoutRequest logoutRequest, String requestReferrer, String issuer) {
		var response = SamlFactory.createResponse(LogoutResponse.class, ssoService.getSloIssuerWithFallback(issuer));
		// we don't know a consumer URL in the config or the LogoutRequest - send it back to the referrer
		response.setDestination(requestReferrer);
		response.setInResponseTo(logoutRequest.getID());
		return response;
	}

	private static <T extends StatusResponseType> String getDestination(T response,
			Optional<StateData> idpStateData, CpResponse cpResponse) {
		String consumerUrl;
		if (response instanceof LogoutResponse) {
			consumerUrl = response.getDestination();
		}
		else {
			if (idpStateData.isEmpty()) {
				throw new TechnicalException(String.format("Missing IDP state for response type %s",
						response.getClass().getName()));
			}
			var stateData = idpStateData.get();
			consumerUrl = ResponseFactory.getRpDestination(stateData, cpResponse);
		}
		log.debug("Set SAML POST target from AuthnRequest AssertionConsumerServiceUrl={}", consumerUrl);
		return consumerUrl;
	}

	private void auditResponseToRp(HttpServletRequest httpServletRequest,
			StatusResponseType response, CpResponse cpResponse, StateData stateData) {
		var relyingParty = stateData != null ?
				relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(stateData.getRpIssuer(), null, true)
				: null;
		var auditDto = new OutboundAuditMapper(trustBrokerProperties)
				.mapFrom(stateData)
				.mapFrom(cpResponse)
				.mapFrom(response)
				.mapFrom(httpServletRequest)
				.mapFrom(relyingParty)
				.build();
		auditService.logOutboundFlow(auditDto);
	}

	private void auditResponseFromCp(HttpServletRequest httpServletRequest,
			StatusResponseType response, CpResponse cpResponse, StateData stateData) {
		var relyingParty = stateData != null ?
				relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(stateData.getRpIssuer(), null, true)
				: null;
		var auditDto = new InboundAuditMapper(trustBrokerProperties)
				.mapFrom(stateData)
				.mapFrom(cpResponse)
				.mapFrom(response)
				.mapFrom(httpServletRequest)
				.mapFrom(relyingParty)
				.build();
		auditService.logInboundSamlFlow(auditDto);
	}

	// Handling interactive profile selection from UI with data from the session
	public String sendResponseWithSelectedProfile(OutputService outputService, ProfileRequest profileRequest,
			HttpServletRequest request, HttpServletResponse response) {
		// input
		var profileRequestId = profileRequest.getStateId();
		SamlValidationUtil.validateProfileRequestId(profileRequestId);

		// state from interactive profile selection handling
		var stateData = stateCacheService.find(profileRequestId, this.getClass().getSimpleName());
		var cpResponse = stateData.getCpResponse();

		// selected profile from user via UI
		var selectedProfileId = profileRequest.getProfileId();
		stateData.setSelectedProfileExtId(selectedProfileId);
		var relyingParty = getRelyingParty(stateData);
		var profileSelectionData = ProfileSelectionData.builder()
		    	.profileSelectionProperties(relyingParty.getProfileSelection())
				.selectedProfileId(selectedProfileId)
				.enforceSingleProfile(true)
				.exchangeId(stateData.getSpStateData().getRelayState())
				.oidcClientId(stateData.getRpOidcClientId())
				.build();
		var psResult = profileSelectionService.doFinalProfileSelection(profileSelectionData, relyingParty, cpResponse, stateData);
		updateAttributes(psResult, cpResponse);
		var incomingDeviceId = WebSupport.getDeviceId(request);

		// handle SAML response from state
		ResponseData<Response> responseData = ResponseData.of(null, profileRequestId, null);
		return sendSuccessSamlResponseToRp(outputService, responseData, cpResponse, stateData, request, response,
				selectedProfileId, incomingDeviceId);
	}

	public void sendResponseToRpFromSessionState(OutputService outputService, RelyingParty relyingParty, StateData idpStateData,
			HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
		var cpResponse = idpStateData.getCpResponse();

		// now we can create the SAML response
		var samlResponse = createSignedSamlResponse(cpResponse, idpStateData);

		// check SSO after the AR and IDM update
		establishSsoOrInvalidateState(relyingParty, idpStateData, !cpResponse.isAborted());

		var encodingParameters = buildEncodingParameters(relyingParty, idpStateData, null);

		log.debug("Response sent for cpIssuer={} rpIssuer={} subjectNameId={} aborted={}",
				cpResponse.getIssuer(), relyingParty.getId(), cpResponse.getNameId(), cpResponse.isAborted());
		var responseData = ResponseData.of(samlResponse, null, null);
		sendResponseToRp(responseData, cpResponse, Optional.of(idpStateData), httpServletRequest, httpServletResponse,
				encodingParameters, outputService);
	}

	public void reloadIdmData(RelyingParty relyingParty, StateData idpStateData) {
		// re-fetch IDM data, usually after access request
		var cpResponse = idpStateData.getCpResponse();
		fetchIdmData(cpResponse, idpStateData, relyingParty.getClientName());
	}

	// works for SAML messages created by XTB
	public String findRelyingPartyIdForTrustbrokerSamlObject(SAMLObject samlObject) {
		Optional<StateData> stateData = Optional.empty();
		if (samlObject instanceof StatusResponseType response) {
			var authnRequestId = response.getInResponseTo();
			stateData = stateCacheService.findBySpId(authnRequestId, this.getClass().getSimpleName());
		}
		else if (samlObject instanceof RequestAbstractType request) {
			var sessionId = request.getID();
			stateData = stateCacheService.findValidState(sessionId, this.getClass().getSimpleName());
		}
		if (stateData.isPresent()) {
			String rpIssuerId = stateData.get().getRpIssuer();
			log.debug("Found rpIssuerId={} from sessionId={}", rpIssuerId, stateData.get().getId());
			return rpIssuerId;
		}
		return null;
	}

}
