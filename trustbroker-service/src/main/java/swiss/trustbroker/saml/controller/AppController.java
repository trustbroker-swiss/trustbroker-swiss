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

package swiss.trustbroker.saml.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.binding.SAMLBindingSupport;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.saml.dto.SignatureContext;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.service.FederationMetadataService;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.saml.dto.ResponseData;
import swiss.trustbroker.saml.service.ArtifactResolutionService;
import swiss.trustbroker.saml.service.AuthenticationService;
import swiss.trustbroker.saml.service.RelyingPartyService;
import swiss.trustbroker.saml.service.SamlOutputService;
import swiss.trustbroker.sso.service.SsoService;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.SamlValidator;
import swiss.trustbroker.util.WebSupport;

/**
 * This is the main controller for SAML POST and federation metadata related interaction.
 */
@Controller
public class AppController extends AbstractSamlController {

	private final RelyingPartyService relyingPartyService;

	private final FederationMetadataService federationMetadataService;

	private final RelyingPartySetupService relyingPartySetupService;

	private final SsoService ssoService;

	private final AuthenticationService authenticationService;

	private final ArtifactResolutionService artifactResolutionService;

	private final SamlOutputService samlOutputService;

	@Autowired
	public AppController(
			RelyingPartyService relyingPartyService,
			TrustBrokerProperties trustBrokerProperties,
			SamlValidator samlValidator,
			FederationMetadataService federationMetadataService,
			RelyingPartySetupService relyingPartySetupService,
			SsoService ssoService,
			ArtifactResolutionService artifactResolutionService,
			AuthenticationService authenticationService,
			SamlOutputService samlOutputService) {
		super(trustBrokerProperties, samlValidator);
		this.relyingPartyService = relyingPartyService;
		this.federationMetadataService = federationMetadataService;
		this.relyingPartySetupService = relyingPartySetupService;
		this.ssoService = ssoService;
		this.artifactResolutionService = artifactResolutionService;
		this.authenticationService = authenticationService;
		this.samlOutputService = samlOutputService;
	}

	/**
	 * Web traffic dispatcher handling SAML POST and UI interaction. Note that we offer the /trustbroker alternative for backward
	 * compat and to possibly get out of the ADFS's way for migration if running on same host name
	 *
	 * @param request  is the web input according to servlet spec 3.x
	 * @param response is the web response according to servlet spec 3.x
	 * @return redirect routing or null when no redirect is needed.
	 */
	@PostMapping(path = { ApiSupport.SAML_API, WebSupport.ADFS_ENTRY_URL,
			WebSupport.ADFS_ENTRY_URL_TRAILING_SLASH, WebSupport.XTB_LEGACY_ENTRY_URL },
			consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
	public String handleIncomingPostMessages(HttpServletRequest request, HttpServletResponse response) {
		return handleIncomingMessage(request, response, false);
	}

	/**
	 * Web traffic dispatcher handling SAML Redirect and UI interaction. Note that we offer the /trustbroker alternative for
	 * backward compat and to possibly get out of the ADFS's way for migration if running on same host name
	 *
	 * @param request  is the web input according to servlet spec 3.x
	 * @param response is the web response according to servlet spec 3.x
	 * @return redirect routing or null when no redirect is needed.
	 */
	@GetMapping(path = { ApiSupport.SAML_API, WebSupport.ADFS_ENTRY_URL, WebSupport.XTB_LEGACY_ENTRY_URL })
	public String handleIncomingGetMessages(HttpServletRequest request, HttpServletResponse response) {
		return handleIncomingMessage(request, response, true);
	}

	private String handleIncomingMessage(HttpServletRequest request, HttpServletResponse response, boolean isGet) {
		MessageContext messageContext;
		SignatureContext signatureContext;
		if (OpenSamlUtil.isSamlArtifactRequest(request)) {
			messageContext = artifactResolutionService.decodeSamlArtifactRequest(request);
			signatureContext = SignatureContext.forArtifactBinding();
		}
		else if (isGet && !OpenSamlUtil.isSamlRedirectRequest(request)) {
			throw new RequestDeniedException(String.format(
					"GET %s without any SAML message dropped", request.getRequestURI()));
		}
		else if (isGet) {
			messageContext = OpenSamlUtil.decodeSamlRedirectMessage(request);
			signatureContext = SignatureContext.forRedirectBinding(WebUtil.getUrlWithQuery(request));
		}
		else {
			messageContext = OpenSamlUtil.decodeSamlPostMessage(request);
			signatureContext = SignatureContext.forPostBinding();
		}
		return processMessageContext(messageContext, response, request, signatureContext);
	}

	private String processMessageContext(MessageContext messageContext, HttpServletResponse response,
			HttpServletRequest request, SignatureContext signatureContext) {

		SAMLObject message = decodeAndValidateMessage(messageContext);

		if (message instanceof AuthnRequest authnRequest) {
			var redirectUrl = authenticationService.handleAuthnRequest(samlOutputService, authnRequest, request, response,
					signatureContext);
			return WebSupport.getViewRedirectResponse(redirectUrl);
		}
		else if (message instanceof Response samlResponse) {
			var relayState = OpenSamlUtil.extractRelayStateAsSessionId(messageContext);
			var redirectUrl =  authenticationService.handleSamlResponse(samlOutputService,
					ResponseData.of(samlResponse, relayState, signatureContext), request, response);
			return WebSupport.getViewRedirectResponse(redirectUrl);
		}
		else if (message instanceof LogoutResponse logoutResponse) {
			var relayState = OpenSamlUtil.extractRelayStateAsSessionId(messageContext);
			ssoService.handleLogoutResponse(logoutResponse, relayState, request);
		}
		else if (message instanceof LogoutRequest logoutRequest) {
			var requestRelayState = SAMLBindingSupport.getRelayState(messageContext);
			relyingPartyService.handleLogoutRequest(samlOutputService, logoutRequest, requestRelayState,
					request, response, signatureContext);
		}
		else {
			handleUnsupportedMessage(message);
		}
		return null;
	}

	private SAMLObject decodeAndValidateMessage(MessageContext messageContext) {
		SAMLObject message = decodeSamlMessage(messageContext);
		validateSamlMessage(message, relyingPartySetupService.getPartySecurityPolicies(message));
		return message;
	}

	// Federation metadata endpoint XML
	@GetMapping(path = {
			ApiSupport.METADATA_URL,
			WebSupport.LOWER_CASE_METADATA_ENDPOINT,
			WebSupport.XTB_ALTERNATE_METADATA_ENDPOINT // camel-case deprecated but documented in old MS docs
	}, produces = MediaType.APPLICATION_XML_VALUE)
	@ResponseBody
	public String handleFederationMetadata(HttpServletRequest request, HttpServletResponse response) {
		return federationMetadataService.getFederationMetadata();
	}


	// Use @Endpoint instead? Would require tweaking interceptor chain (see WsTrustEndpoint etc. via Spring EndpointMapping)
	@PostMapping(path = ApiSupport.ARP_URL)
	public void resolveArtifact(HttpServletRequest request, HttpServletResponse response) {
		artifactResolutionService.resolveArtifact(request, response);
	}

}
