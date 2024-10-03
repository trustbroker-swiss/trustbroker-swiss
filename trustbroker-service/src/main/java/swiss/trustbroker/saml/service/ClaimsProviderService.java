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

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.springframework.stereotype.Service;
import swiss.trustbroker.api.saml.dto.DestinationType;
import swiss.trustbroker.api.saml.dto.EncodingParameters;
import swiss.trustbroker.api.saml.service.OutputService;
import swiss.trustbroker.audit.dto.EventType;
import swiss.trustbroker.audit.service.AuditService;
import swiss.trustbroker.audit.service.OutboundAuditMapper;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.SsoSessionIdPolicy;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.script.service.ScriptService;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.sessioncache.service.StateCacheService;
import swiss.trustbroker.util.WebSupport;


@Service
@AllArgsConstructor
@Slf4j
public class ClaimsProviderService {

	private final StateCacheService stateCacheService;

	private final TrustBrokerProperties trustBrokerProperties;

	private final RelyingPartySetupService relyingPartySetupService;

	private final AuditService auditService;

	private final ScriptService scriptService;

	private AuthnRequest createAndSignCpAuthnRequest(StateData stateData, String rpIssuer, String rpReferrer,
													 String cpIssuer, boolean delegateOrigin) {
		var authnRequest = OpenSamlUtil.buildSamlObject(AuthnRequest.class);
		authnRequest.setIssueInstant(Instant.now());
		var claimsProvider = relyingPartySetupService.getClaimsProviderSetupById(cpIssuer);
		if (claimsProvider.isEmpty()) {
			throw new RequestDeniedException(String.format(
					"Missing CP with cpIssuer='%s' (check SetupCP.xml)", StringUtil.clean(cpIssuer)));
		}
		var ssoUrl = claimsProvider.get().getSsoUrl();
		if (ssoUrl == null) {
			throw new RequestDeniedException(String.format(
					"Missing SSOUrl for CP with cpIssuer='%s' (check SetupCP.xml)", cpIssuer));
		}
		String consumerUrl = trustBrokerProperties.getSamlConsumerUrl();
		authnRequest.setDestination(ssoUrl);
		authnRequest.setID(stateData.getId()); // Tricky: cpRelayState, CpAuthnRequest.ID and SSO cookie all have the same value
		var authnRequestIssuerId = claimsProvider.get().getAuthnRequestIssuerId(trustBrokerProperties.getIssuer());
		log.debug("Using authnRequestIssuerId={} for cpIssuerId={}", authnRequestIssuerId, cpIssuer);
		authnRequest.setIssuer(SamlFactory.createIssuer(authnRequestIssuerId));
		authnRequest.setNameIDPolicy(SamlFactory.createNameIdPolicy(NameIDType.UNSPECIFIED));
		authnRequest.setRequestedAuthnContext(createAuthnContext(stateData));

		// scopes support
		if (delegateOrigin) {
			authnRequest.setScoping(SamlFactory.createScoping(rpIssuer));
			log.debug("Setting rpIssuerId={} as Scoping", rpIssuer);
		}

		setForceAuthnAndACUrl(stateData, authnRequest, consumerUrl, cpIssuer);

		// Script hook
		scriptService.processRequestToCp(cpIssuer, authnRequest);

		var cp = relyingPartySetupService.getClaimsProviderSetupByIssuerId(cpIssuer, null);
		var credential = relyingPartySetupService.getRelyingPartySigner(rpIssuer, rpReferrer);
		var signatureParameters = cp.getSignatureParametersBuilder()
				.credential(credential)
				.skinnyAssertionNamespaces(trustBrokerProperties.getSkinnyAssertionNamespaces())
				.build();
		SamlFactory.signSignableObject(authnRequest, signatureParameters);

		return authnRequest;
	}

	private void setForceAuthnAndACUrl(StateData stateData, AuthnRequest authnRequest,  String consumerURL, String cpIssuer) {
		var disableACUrl = relyingPartySetupService.disableAcUrl(cpIssuer, null);
		if (stateData.getForceAuthn() != null) {
			authnRequest.setForceAuthn(stateData.getForceAuthn());
		}
		if (!disableACUrl) {
			authnRequest.setAssertionConsumerServiceURL(consumerURL);
		}
	}

	static RequestedAuthnContext createAuthnContext(StateData stateData) {
		var contextClasses = getAuthnContextClassRefs(stateData);
		if (contextClasses.isEmpty()) {
			// do not add an empty <samlp:RequestedAuthnContext/> to any CP side AuthnRequest (looks unclean and may be CP cares)
			return null;
		}

		var requestedAuthnContext = OpenSamlUtil.buildSamlObject(RequestedAuthnContext.class);
		requestedAuthnContext.getAuthnContextClassRefs().addAll(contextClasses);

		// Specified additional comparison operator
		if (stateData.getComparisonType() != null) {
			var comparison = AuthnContextComparisonTypeEnumeration.valueOf(stateData.getComparisonType().toUpperCase());
			requestedAuthnContext.setComparison(comparison);
		}

		return requestedAuthnContext;
	}

	private static List<AuthnContextClassRef> generateAuthContextClassRefsFromList(List<String> contextClasses) {
		List<AuthnContextClassRef> authnContextClassRefs = new ArrayList<>();
		for (String contextClass : contextClasses) {
			var authnContextClassRef = OpenSamlUtil.buildSamlObject(AuthnContextClassRef.class);
			authnContextClassRef.setURI(contextClass);
			authnContextClassRefs.add(authnContextClassRef);
		}
		return authnContextClassRefs;
	}

	private static List<AuthnContextClassRef> getAuthnContextClassRefs(StateData stateData) {
		StateData spStateData = stateData.getSpStateData();
		if (spStateData == null || spStateData.getContextClasses() == null) {
			return new ArrayList<>();
		}
		List<String> contextClasses = spStateData.getContextClasses();
		return generateAuthContextClassRefsFromList(contextClasses);
	}

	private void redirectUserWithRequest(AuthnRequest authnRequest, HttpServletResponse httpServletResponse,
			String claimUrn, String rpUrn, String rpReferer, StateData idpStateData, OutputService outputService) {
		var claimsProvider = relyingPartySetupService.getClaimsProviderSetupById(claimUrn);
		var useArtifactBinding = useArtifactBinding(claimsProvider, idpStateData);
		var idpSsoDestination = claimsProvider.isPresent() ? claimsProvider.get().getSsoUrl() : null;
		var credential = relyingPartySetupService.getRelyingPartySigner(rpUrn, rpReferer);
		var encodingParameters = EncodingParameters.builder().useArtifactBinding(useArtifactBinding).build();
		outputService.sendRequest(authnRequest, credential, idpStateData.getRelayState(), idpSsoDestination,
				httpServletResponse, encodingParameters, DestinationType.CP);
	}

	static boolean useArtifactBinding(Optional<ClaimsParty> claimsParty, StateData stateData) {
		var initiatedViaArtifactBinding =
				stateData != null && Boolean.TRUE.equals(stateData.getSpStateData().getInitiatedViaArtifactBinding());
		var useArtifactBinding = claimsParty.isPresent() && claimsParty.get().getSamlArtifactBinding() != null &&
				claimsParty.get().getSamlArtifactBinding().useArtifactBinding(initiatedViaArtifactBinding);
		if (useArtifactBinding) {
			log.debug(
					"Use artifact binding for AuthnRequest with cpIssuerId={} artifactBinding={} initiatedViaArtifactBinding={}"
							+ " artifactBindingTrigger=session_rp_binding",
					claimsParty.get().getId(), claimsParty.get().getSamlArtifactBinding(), initiatedViaArtifactBinding);
		}
		return useArtifactBinding;
	}

	private void saveCorrelatedIdpStateDataWithState(String cpIssuerId, String deviceID, StateData stateData) {
		// update session validity
		var now = OffsetDateTime.now();
		stateData.setIssueInstant(now.toString());
		stateData.setIssuer(cpIssuerId);
		if (deviceID != null) {
			stateData.setDeviceId(deviceID);
		}

		// set an initial session context to be sent to RP if not yet done, override in SSOService.establishSso
		if (stateData.getSsoSessionId() == null) {
			stateData.setSsoSessionId(
					SsoSessionIdPolicy.generateSsoId(false, trustBrokerProperties.getSsoSessionIdPolicy()));
		}

		// save initial data to DB
		stateCacheService.save(stateData, this.getClass().getSimpleName());
	}

	public void sendSamlToCpWithMandatoryIds(
			OutputService outputService,
			HttpServletRequest request,
			HttpServletResponse response,
			StateData stateData,
			String claimUrn) {
		// validate
		log.debug("Redirect user to CP claimUrn={} based on rpAuthnRequestId={}", claimUrn, stateData.getSpStateData().getId());
		if (StringUtils.isBlank(claimUrn)) {
			var msg = String.format("Client call with missing input: claimUrn='%s'", claimUrn);
			throw new RequestDeniedException(msg);
		}
		log.debug("Requesting CP='{}' based on RP='{}' received from client={}",
				claimUrn, stateData.getSpStateData().getId(),
				WebSupport.getClientHint(request, trustBrokerProperties.getNetwork()));
		sendSamlToCp(outputService, request, response, stateData, claimUrn);
	}

	// send SAML POST to browser for IdP redirection
	public void sendSamlToCp(
			OutputService outputService,
			HttpServletRequest request,
			HttpServletResponse response,
			StateData idpStateData,
			String cpIssuer
			) {
		// state from RP
		var deviceId = WebSupport.getDeviceId(request);
		saveCorrelatedIdpStateDataWithState(cpIssuer, deviceId, idpStateData);
		var spStateData = idpStateData.getSpStateData();
		var rpIssuer = spStateData.getIssuer();
		var rpReferrer = spStateData.getReferer();

		// forward
		var authnRequest = createAndSignCpAuthnRequest(idpStateData, rpIssuer, rpReferrer,
				cpIssuer, delegateOrigin(cpIssuer));
		redirectUserWithRequest(authnRequest, response, cpIssuer, rpIssuer, rpReferrer, idpStateData, outputService);

		// audit
		auditAuthnRequestToCp(authnRequest, request, idpStateData);
	}

	// Pass on rpIssuer to CP in Scoping element
	private boolean delegateOrigin(String cpIssuer) {
		var claimsParty = relyingPartySetupService.getClaimsProviderSetupById(cpIssuer);
		return claimsParty.isPresent() && claimsParty.get().isDelegateOrigin();
	}

	private void auditAuthnRequestToCp(AuthnRequest authnRequest, HttpServletRequest request, StateData stateData) {
		var relyingParty = stateData != null ?
				relyingPartySetupService.getRelyingPartyByIssuerIdOrReferrer(stateData.getRpIssuer(),	null,	true)
				: null;
		var auditDto = new OutboundAuditMapper(trustBrokerProperties)
				.mapFrom(authnRequest)
				.mapFrom(stateData) // overrides authnRequest conversationId if CP side
				.mapFrom(request)
				.mapFrom(relyingParty)
				.build();
		// stateData may have overridden the SAML type if it contains an IDP Response:
		auditDto.setEventType(EventType.AUTHN_REQUEST);
		auditService.logOutboundFlow(auditDto);
	}

}
