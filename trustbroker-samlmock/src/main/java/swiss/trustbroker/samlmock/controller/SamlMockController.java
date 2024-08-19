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

package swiss.trustbroker.samlmock.controller;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.TreeMap;
import java.util.UUID;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.xml.SerializeSupport;
import org.apache.hc.core5.net.URIBuilder;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.common.binding.SAMLBindingSupport;
import org.opensaml.saml.common.messaging.context.SAMLBindingContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.ArtifactResolve;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.impl.AuthnRequestImpl;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.saml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.CollectionUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.view.UrlBasedViewResolver;
import org.w3c.dom.Element;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.exception.TrustBrokerException;
import swiss.trustbroker.common.saml.dto.ArtifactPeer;
import swiss.trustbroker.common.saml.dto.ArtifactResolutionParameters;
import swiss.trustbroker.common.saml.dto.SignatureParameters;
import swiss.trustbroker.common.saml.dto.SignatureValidationParameters;
import swiss.trustbroker.common.saml.service.ArtifactCacheService;
import swiss.trustbroker.common.saml.util.CredentialReader;
import swiss.trustbroker.common.saml.util.EncryptionUtil;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.saml.util.SamlIoUtil;
import swiss.trustbroker.common.saml.util.SamlUtil;
import swiss.trustbroker.common.saml.util.SoapUtil;
import swiss.trustbroker.common.setup.service.GitService;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.samlmock.SamlMockProperties;
import swiss.trustbroker.samlmock.dto.SamlMockCpResponse;
import swiss.trustbroker.samlmock.dto.SamlMockRpRequest;

/**
 * This controller handles all the mock services from RP -> XTB and CP -> XTB
 */
@Controller
@Slf4j
public class SamlMockController {

	// 2min before XTB blocks and reload is required
	private static final int MAX_AUTHN_REQUEST_VALIDITY_SEC = 120;

	// 2h before XTB blocks and E2E auth needs to be restarted
	private static final int MAX_ASSERTION_VALIDITY_SEC = 7200;

	private static final String REQUEST_DIRECTORY = "/request/";

	private static final String RESPONSE_DIRECTORY = "/response/";

	private static final String SAML_POST_TARGET_URL = "samlPostTargetUrl";

	private static final String RELAY_STATE_PREFIX = "RELAY_";

	private static final String AUTHN_REQUEST_ID_PREFIX = "AuthnRequest_";

	private static final String NAVIGATE_RESPONSE_FROM_XTB = "responseFromXTB";

	private static final String NAVIGATE_SELECT_AUTHN_REQ = "selectRequest";

	private static final String NAVIGATE_SELECT_RESPONSE = "selectResponse";

	private static final String NAVIGATE_REFRESH_MOCK_DATA = "refreshMockData";

	private static final String TB_APPLICATION_URL = "tbApplicationUrl";

	private static final int ENDPOINT_INDEX = 0;

	private static final List<String> SUPPORTED_SAML_BINDINGS = List.of(
			SAMLConstants.SAML2_POST_BINDING_URI,
			SAMLConstants.SAML2_REDIRECT_BINDING_URI,
			SAMLConstants.SAML2_ARTIFACT_BINDING_URI);

	private final GitService gitService;

	private final SamlMockProperties properties;

	private final Random random;

	private final ArtifactCacheService artifactCacheService;

	private final VelocityEngine velocityEngine;

	@SuppressWarnings("java:S2245") // insecure random is fine for the mock
	public SamlMockController(GitService gitService, SamlMockProperties properties, ArtifactCacheService artifactCacheService,
			VelocityEngine velocityEngine) {
		this.gitService = gitService;
		this.properties = properties;
		this.artifactCacheService = artifactCacheService;
		this.velocityEngine = velocityEngine;
		random = new Random();
	}

	private String getMockDirectoryPath(String which) {
		return properties.getMockDataDirectory() + which;
	}

	private String getSpSignerKeystorePath() {
		return properties.getKeystoreDirectory() + properties.getSpSignerKeystore();
	}

	private String getIdpSignerKeystorePath() {
		return properties.getKeystoreDirectory() + properties.getIdpSignerKeystore();
	}

	private String getEncryptionKeystorePath() {
		return properties.getKeystoreDirectory() + properties.getEncryptionKeystore();
	}

	@GetMapping(path = "/")
	public String homePage(Model model) {
		return showAllSamples(model);
	}

	@GetMapping(path = "/authn/samples")
	public String showAllSamples(Model model) {
		try {
			var uuid = UUID.randomUUID();
			String[] sampleFiles = listDirectoryContent(getMockDirectoryPath(REQUEST_DIRECTORY));
			Map<String, SamlMockRpRequest> sampleMap = getEncodedRequestMap(sampleFiles, uuid);
			model.addAttribute("requests", sampleMap);
			model.addAttribute(TB_APPLICATION_URL, properties.getTbApplicationUrl());
			model.addAttribute("testCpIssuer", properties.getTestCpIssuer());
			model.addAttribute("testRpIssuer", properties.getTestRpIssuer());
			return NAVIGATE_SELECT_AUTHN_REQ;
		}
		catch (TrustBrokerException e) {
			log.error("Loading request samples failed: {}", e.getInternalMessage());
			throw e;
		}
	}

	@GetMapping(path = "/auth/saml2/idp/samples")
	public String mockCpResponseCpInitiated(Model model) {
		try {
			var acsUrl = properties.getConsumerUrl();
			var relayState = "MOCK_" + UUID.randomUUID();
			return mockCpResponseProcessing(model, acsUrl, null, null, relayState, properties.isKeepSampleUrlsforCpInitiated());
		}
		catch (TrustBrokerException e) {
			log.error("Loading response samples failed: {}", e.getInternalMessage());
			throw e;
		}
	}

	@PostMapping(path = "/auth/saml2/idp/samples")
	public String mockCpResponse(Model model, HttpServletRequest request) {
		try {
			var peer = buildArtifactPeer(true);
			var messageContext = decodeSamlMessage(request, peer);
			var samlRequest = (RequestAbstractType) messageContext.getMessage();
			var requestId = samlRequest.getID();
			var acsUrl = request.getParameter(HttpHeaders.REFERER);
			if (samlRequest instanceof AuthnRequest authnRequest) {
				acsUrl = authnRequest.getAssertionConsumerServiceURL();
			}
			var relayState = SAMLBindingSupport.getRelayState(messageContext);
			return mockCpResponseProcessing(model, acsUrl, samlRequest.getIssuer(), requestId, relayState, false);
		}
		catch (TrustBrokerException e) {
			log.error("Loading response samples failed: {}", e.getInternalMessage());
			throw e;
		}
	}

	private String mockCpResponseProcessing(Model model, String acsUrl, Issuer samlRequestIssuer, String requestId,
			String relayState, boolean keepSampleUrls) {
		String[] sampleFiles = listDirectoryContent(getMockDirectoryPath(RESPONSE_DIRECTORY));

		String requestIssuer = getAuthnRequestIssuer(samlRequestIssuer, properties.getIssuer());
		Map<String, SamlMockCpResponse> responses = getEncodedResponseMap(sampleFiles, requestId, acsUrl,
				relayState, requestIssuer, keepSampleUrls);
		model.addAttribute("responses", responses);
		model.addAttribute(TB_APPLICATION_URL, properties.getTbApplicationUrl());
		return NAVIGATE_SELECT_RESPONSE;
	}

	@GetMapping(path = "/saml/metadata", produces = MediaType.APPLICATION_XML_VALUE)
	public String handleMetadata() {
		try {
			var entityDescriptor = generateMetadata();
			var domDescriptor = SamlUtil.marshallMessage(entityDescriptor);
			SamlUtil.removeNewLinesFromCertificates(domDescriptor);
			return SerializeSupport.prettyPrintXML(domDescriptor);
		}
		catch (MessageEncodingException e) {
			log.error("Could not generate metadata: {}", e.getMessage(), e);
			throw new TechnicalException("Could not generate metadata: " + e);
		}
	}

	private EntityDescriptor generateMetadata() {
		EntityDescriptor descriptor = OpenSamlUtil.buildSamlObject(EntityDescriptor.class);
		descriptor.setID(buildSourceId());
		descriptor.setEntityID(properties.getArtifactResolutionIssuer());

		var idpSsoDescriptor = buildIdpSsoDescriptor();
		idpSsoDescriptor.getKeyDescriptors()
						.add(getKeyDescriptor(givenResponseCredential(), UsageType.SIGNING));
		idpSsoDescriptor.getKeyDescriptors()
						.add(getKeyDescriptor(givenEncryptionCredential(), UsageType.ENCRYPTION));
		descriptor.getRoleDescriptors()
				  .add(idpSsoDescriptor);
		var spSsoDescriptor = buildSpSsoDescriptor();
		spSsoDescriptor.getKeyDescriptors()
					   .add(getKeyDescriptor(givenAuthnRequestCredential(), UsageType.SIGNING));
		spSsoDescriptor.getKeyDescriptors()
					   .add(getKeyDescriptor(givenEncryptionCredential(), UsageType.ENCRYPTION));
		descriptor.getRoleDescriptors()
				  .add(spSsoDescriptor);

		var credential = givenResponseCredential(); // re-use response signer for metadata
		var signature = SamlFactory.prepareSignableObject(
				descriptor, credential, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, null, null);
		SamlUtil.signSamlObject(descriptor, signature);
		return descriptor;
	}

	private static KeyDescriptor getKeyDescriptor(Credential credential, UsageType usageType) {
		KeyDescriptor keyDescriptor = OpenSamlUtil.buildSamlObject(KeyDescriptor.class);
		KeyInfo keyInfo = SamlFactory.createKeyInfo(credential);
		keyDescriptor.setUse(usageType);
		keyDescriptor.setKeyInfo(keyInfo);
		return keyDescriptor;
	}


	private String buildSourceId() {
		var arIssuer = properties.getArtifactResolutionIssuer();
		if (arIssuer == null) {
			throw new TechnicalException("Missing artifactResolutionIssuer in config");
		}
		return OpenSamlUtil.calculateArtifactSourceIdFromIssuerId(arIssuer);
	}

	private IDPSSODescriptor buildIdpSsoDescriptor() {
		IDPSSODescriptor idpDescriptor = OpenSamlUtil.buildSamlObject(IDPSSODescriptor.class);
		idpDescriptor.setWantAuthnRequestsSigned(true);
		idpDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
		var artifactResolutionService = buildArtifactResolutionService();
		idpDescriptor.getArtifactResolutionServices()
					 .add(artifactResolutionService);
		for (String binding : SUPPORTED_SAML_BINDINGS) {
			idpDescriptor.getSingleLogoutServices()
						 .add(getSingleLogoutService(properties.getIdpServiceUrl(), binding));
			idpDescriptor.getSingleSignOnServices()
						 .add(getSingleSignOnService(properties.getIdpServiceUrl(), binding));
		}
		return idpDescriptor;
	}

	private SPSSODescriptor buildSpSsoDescriptor() {
		var spssoDescriptor = OpenSamlUtil.buildSamlObject(SPSSODescriptor.class);
		spssoDescriptor.setAuthnRequestsSigned(true);
		spssoDescriptor.setWantAssertionsSigned(true);
		spssoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

		for (String binding : SUPPORTED_SAML_BINDINGS) {
			spssoDescriptor.getSingleLogoutServices()
						   .add(
								   getSingleLogoutService(properties.getAssertionConsumerServiceUrl(), binding));
			var index = spssoDescriptor.getAssertionConsumerServices()
									   .size();
			spssoDescriptor.getAssertionConsumerServices()
						   .add(
								   getAssertionConsumerService(properties.getAssertionConsumerServiceUrl(), binding, index));
		}
		return spssoDescriptor;
	}

	private static SingleSignOnService getSingleSignOnService(String location, String binding) {
		SingleSignOnService sso = OpenSamlUtil.buildSamlObject(SingleSignOnService.class);
		sso.setLocation(location);
		sso.setBinding(binding);
		return sso;
	}

	private static SingleLogoutService getSingleLogoutService(String location, String binding) {
		SingleLogoutService sso = OpenSamlUtil.buildSamlObject(SingleLogoutService.class);
		sso.setLocation(location);
		sso.setBinding(binding);
		return sso;
	}

	private static AssertionConsumerService getAssertionConsumerService(String location, String binding, int index) {
		AssertionConsumerService assertionConsumerService = OpenSamlUtil.buildSamlObject(AssertionConsumerService.class);
		assertionConsumerService.setLocation(location);
		assertionConsumerService.setBinding(binding);
		assertionConsumerService.setIndex(index);
		return assertionConsumerService;
	}

	private ArtifactResolutionService buildArtifactResolutionService() {
		var artifactResolutionService = OpenSamlUtil.buildSamlObject(ArtifactResolutionService.class);
		artifactResolutionService.setBinding(SAMLConstants.SAML2_SOAP11_BINDING_URI);
		artifactResolutionService.setLocation(properties.getArtifactResolutionServiceUrl());
		artifactResolutionService.setIndex(ENDPOINT_INDEX);
		return artifactResolutionService;
	}

	// SOAP request - manual implementation for mock to avoid a separate @Endpoint
	@PostMapping(path = "/authn/arp")
	public void resolveArtifact(HttpServletRequest request, HttpServletResponse response) throws IOException {
		try {
			var artifactResolve = SoapUtil.extractSamlObjectFromEnvelope(request.getInputStream(), ArtifactResolve.class);
			var artifactId = artifactResolve.getArtifact().getValue();
			log.info("Received ArtifactResolve with id={} from issuerId={} for artifact={}",
					artifactResolve.getID(), artifactResolve.getIssuer().getValue(), artifactId);

			var message = artifactCacheService.retrieveArtifact(artifactId);
			if (message.isPresent() && message.get() instanceof SignableSAMLObject samlObject && !samlObject.isSigned()) {
				resignSamlObject(samlObject);
			}
			var artifactResponse = SamlFactory.createArtifactResponse(
					artifactResolve, message, properties.getArtifactResolutionIssuer());
			resignSamlObject(artifactResponse);
			SoapUtil.sendSoap11Response(response, artifactResponse);
			artifactCacheService.removeArtifact(artifactId);
			log.info("Sent ArtifactResponse for artifact={}", artifactResolve.getArtifact());
		}
		catch (TrustBrokerException e) {
			log.error("Handling artifact resolve failed: {}", e.getInternalMessage());
			throw e;
		}
	}

	private static String getAuthnRequestIssuer(Issuer issuer, String confIssuer) {
		if (issuer == null) {
			return confIssuer;
		}
		return issuer.getValue();
	}

	// endpoint for system test: processes a SAML POST request, stores the message in the artifact map, and
	// returns a SAML artifact request that can be forwarded to the target recipient
	@PostMapping(path = "/authn/artifact")
	public void cacheArtifact(HttpServletRequest request, HttpServletResponse response) {
		try {
			var messageContext = OpenSamlUtil.decodeSamlPostMessage(request);
			var endpointUrl = calculateEndpoint(request, messageContext);
			var issuer = calculateIssuer(messageContext);
			var relayState = SAMLBindingSupport.getRelayState(messageContext);
			log.info("Received SAML POST message of type={} for endpoint={} relayState={} issuer={}",
					messageContext.getMessage().getClass().getName(), endpointUrl, relayState, issuer);
			var arParams = buildArtifactResolutionParameters();
			var context = OpenSamlUtil.createMessageContext((SAMLObject) messageContext.getMessage(), null, endpointUrl,
					relayState);
			OpenSamlUtil.initAndEncodeSamlArtifactMessage(response, context, issuer, velocityEngine,
					arParams, artifactCacheService.getArtifactMap());
			log.info("Returned SAML artifact message with artifactIssuer={} to sender", properties.getArtifactResolutionIssuer());
		}
		catch (TrustBrokerException e) {
			log.error("Handling artifact request failed: {}", e.getInternalMessage());
			throw e;
		}

	}

	private static String calculateIssuer(MessageContext messageContext) {
		if (messageContext.getMessage() instanceof RequestAbstractType samlMessage) {
			return samlMessage.getIssuer()
							  .getValue();
		}
		if (messageContext.getMessage() instanceof StatusResponseType samlMessage) {
			return samlMessage.getIssuer()
							  .getValue();
		}
		throw new RequestDeniedException(String.format("Invalid type class=%s",
				messageContext.getMessage()
							  .getClass()
							  .getName()));
	}

	private static String calculateEndpoint(HttpServletRequest request, MessageContext messageContext) {
		var endpoint = OpenSamlUtil.getEndpoint(messageContext);
		var endpointUrl = request.getHeader(HttpHeaders.REFERER);
		log.debug("Request referrerUrl={}", endpointUrl);
		if (endpoint != null) {
			endpointUrl = endpoint.getLocation();
			log.debug("Request endpointUrl={}", endpointUrl);
		}
		// endpoint is mandatory for the response, just use our URL if the calling test did not provide anything else
		if (endpointUrl == null) {
			endpointUrl = request.getRequestURI();
			log.debug("Request uri={}", endpointUrl);
		}
		return endpointUrl;
	}

	// Display the returned XTB SAMl Response in the UI on RP side.
	// For LogoutResponse the destination is the referrer + /auth/saml2/slo when not explicitly configured on XTB
	// /auth/saml2/slo used by some clients supported as well.
	@PostMapping(path = { "/authn/consumer", "/auth/saml2/slo", "/auth/saml/slo" })
	public String mockAssertionConsumer(Model model, HttpServletRequest request)
			throws MessageEncodingException {
		var messageXml = validateResponseAndExtractMessage(request);

		model.addAttribute(SamlIoUtil.SAML_RESPONSE_NAME, messageXml);
		model.addAttribute(SAML_POST_TARGET_URL, properties.getSamlPostTargetUrl());
		model.addAttribute(TB_APPLICATION_URL, properties.getTbApplicationUrl());
		return NAVIGATE_RESPONSE_FROM_XTB;
	}

	@GetMapping(path = "/auth/http/slo")
	public String mockSloNotificationConsumer(HttpServletRequest request) {
		if (log.isInfoEnabled()) {
			log.info("Received HTTP GET single logout notification from referrer={}",
					StringUtil.clean(request.getParameter(HttpHeaders.REFERER)));
		}
		return NAVIGATE_RESPONSE_FROM_XTB;
	}

	@GetMapping(path = "/auth/oidc/slo")
	public String mockSloOidcNotificationConsumer(HttpServletRequest request) {
		var issuerId = request.getParameter("iss");
		var sessionId = request.getParameter("sid");
		if (log.isInfoEnabled()) {
			log.info("Received OIDC GET single logout notification for issuerId={} sessionId={} from referrer={}",
					StringUtil.clean(issuerId), StringUtil.clean(sessionId),
					StringUtil.clean(request.getParameter(HttpHeaders.REFERER)));
		}
		return NAVIGATE_RESPONSE_FROM_XTB;
	}

	@PostMapping(path = { "/accessrequest/consumer" })
	public String mockAccessRequestConsumer(HttpServletRequest request)
			throws MessageEncodingException {
		try {
			validateResponseAndExtractMessage(request);

			var application = getMandatoryQueryParameter(request, "appl");
			var language = getMandatoryQueryParameter(request, "language");
			var cicd = getMandatoryQueryParameter(request, "CICD");
			var returnUrl = getMandatoryQueryParameter(request, "returnURL");
			if (log.isInfoEnabled()) {
				log.info("Received access request for application={}, language={}, CICD={}, returning to {}",
						StringUtil.clean(application), StringUtil.clean(language), StringUtil.clean(cicd),
						StringUtil.clean(returnUrl));
			}
			return UrlBasedViewResolver.REDIRECT_URL_PREFIX + returnUrl;
		}
		catch (TrustBrokerException e) {
			log.error("Handling access request failed: {}", e.getInternalMessage());
			throw e;
		}
	}

	private static String getMandatoryQueryParameter(HttpServletRequest request, String queryParam) {
		var param = request.getParameter(queryParam);
		if (param == null) {
			throw new TechnicalException(String.format("Missing parameter %s in query: %s", queryParam,
					request.getQueryString()));
		}
		return param;
	}

	private String validateResponseAndExtractMessage(HttpServletRequest request) throws MessageEncodingException {
		var peer = buildArtifactPeer(false);
		var messageContext = decodeSamlMessage(request, peer);
		var samlResponse = (StatusResponseType) messageContext.getMessage();
		final Element domMessage = SamlUtil.marshallMessage(samlResponse);
		final String messageXML = SerializeSupport.prettyPrintXML(domMessage);
		validateResponse(messageContext, samlResponse);
		return messageXML;
	}

	private ArtifactPeer buildArtifactPeer(boolean rpSide) {
		return ArtifactPeer.builder()
						   .metadataUrl(properties.getMetadataUrl())
						   .artifactResolutionUrl(properties.getArpUrl())
						   .peerRole(rpSide ? SPSSODescriptor.DEFAULT_ELEMENT_NAME : IDPSSODescriptor.DEFAULT_ELEMENT_NAME)
						   .build();
	}


	private static void validateResponse(MessageContext messageContext, StatusResponseType samlResponse) {
		var relayState = messageContext.ensureSubcontext(SAMLBindingContext.class)
									   .getRelayState();
		var inResponseTo = samlResponse.getInResponseTo();
		var relayStateOk = relayState != null && relayState.startsWith(RELAY_STATE_PREFIX);
		var inResponseToOk = inResponseTo != null && inResponseTo.startsWith(AUTHN_REQUEST_ID_PREFIX);
		if (!relayStateOk) {
			log.error("Invalid response RelayState: {}", relayState);
		}
		if (!inResponseToOk) {
			log.error("Invalid response InResponseTo: {}", inResponseTo);
		}
		if (relayStateOk && inResponseToOk) {
			var relayStateId = relayState.substring(RELAY_STATE_PREFIX.length());
			var inResponseToId = inResponseTo.substring(AUTHN_REQUEST_ID_PREFIX.length());
			if (relayStateId.equals(inResponseToId)) {
				log.info("Response ID: {}, matching InResponseTo {}, RelayState: {}", samlResponse.getID(), inResponseTo,
						relayState);
			}
			else {
				log.error("Mismatch between RelayState {} and InResponseTo {}", relayState, inResponseTo);
			}
		}
	}

	@GetMapping(path = "/authn/samples/refresh")
	public String refreshMockData() {
		try {
			var configCache = GitService.getConfigCachePath();
			var cacheDir = new File(configCache);
			if (cacheDir.exists() && cacheDir.isDirectory()) {
				gitService.pullConfiguration();
			}
			else {
				gitService.cloneConfiguration();
			}
			return NAVIGATE_REFRESH_MOCK_DATA;
		}
		catch (TrustBrokerException e) {
			log.error("Handling config refresh failed: {}", e.getInternalMessage());
			throw e;
		}
	}

	private Map<String, SamlMockRpRequest> getEncodedRequestMap(String[] fileNames, UUID uuid) {
		Map<String, SamlMockRpRequest> sampleMap = new TreeMap<>();
		if (fileNames != null && fileNames.length > 0) {
			Arrays.stream(fileNames)
					.forEach(fileName -> addRequestFromFile(uuid, sampleMap, fileName));
		}
		return sampleMap;
	}

	private void addRequestFromFile(UUID uuid, Map<String, SamlMockRpRequest> sampleMap, String fileName) {
		var request = SamlIoUtil.unmarshallRequest(getMockDirectoryPath(REQUEST_DIRECTORY) + fileName);
		var sign = true;
		request.setIssueInstant(Instant.now());
		request.setID(AUTHN_REQUEST_ID_PREFIX + uuid);
		if (request instanceof AuthnRequest authnRequest) {
			authnRequest.setAssertionConsumerServiceURL(getAcsUrlForRequest(request));
			setAuthnRequestConditions(authnRequest.getConditions());
			sign = request.getSignature() != null;
		}
		if (sign || properties.isSignAuthnRequest()) {
			resignSamlObject(request);
		}
		try {
			var tbConsumerUrl = request.getDestination();
			// AuthnRequest without a Destination
			if (tbConsumerUrl == null) {
				tbConsumerUrl = properties.getConsumerUrl();
			}

			var encodedPostMessage = SamlUtil.encode(request);
			var rpRequest = new SamlMockRpRequest();
			rpRequest.setSamlPostRequest(encodedPostMessage);
			// The SAML message is commonly not signed for redirect requests as the signature is part of the binding
			request.setSignature(null);
			var relayState = RELAY_STATE_PREFIX + uuid;
			rpRequest.setRelayState(relayState);
			var acsUrl = addUriParameter(tbConsumerUrl, SamlIoUtil.SAML_RELAY_STATE, relayState);
			rpRequest.setAcsUrl(acsUrl);
			var encodedRedirectMessage = SamlIoUtil.encodeSamlRedirectData(request);
			rpRequest.setSamlRedirectRequest(encodedRedirectMessage);
			// arpEntityId (getArtifactResolutionIssuer) determines the RP config used during artifact resolution
			// use the mock ID, so we only need to configure an artifact resolution / metadata URL for this RP
			var encodedArtifactMessage = SamlIoUtil.encodeSamlArtifactData(velocityEngine,
					artifactCacheService.getArtifactMap(), request, buildArtifactResolutionParameters(), relayState);
			rpRequest.setSamlArtifactRequest(encodedArtifactMessage);
			var sigAlg = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1;
			rpRequest.setSigAlg(sigAlg);
			var signature = SamlIoUtil.buildEncodedSamlRedirectSignature(request, givenAuthnRequestCredential(),
					sigAlg, relayState, encodedRedirectMessage);
			rpRequest.setSignature(signature);
			sampleMap.put(fileName, rpRequest);
		}
		catch (MessageEncodingException e) {
			throw new TechnicalException(String.format("Message Encoding exception: %s", e.getMessage()), e);
		}
	}

	private String getAcsUrlForRequest(RequestAbstractType request) {
		if (request instanceof AuthnRequestImpl authnRequest && properties.isUseOriginalAcr()) {
			return authnRequest.getAssertionConsumerServiceURL();
		}
		var acsUrl = properties.getAssertionConsumerServiceUrl();
		// allow two different ACS URLs with the same SamlMock / application
		var localhost = "http://localhost:";
		var localIp = "http://127.0.0.1:";
		if (acsUrl.startsWith(localhost) && request.getDestination() != null && request.getDestination()
																					   .startsWith(localIp)) {
			acsUrl = acsUrl.replace(localhost, localIp);
			log.info("Request targets {}, repointed ACS URL to {}", request.getDestination(), acsUrl);
		}
		return acsUrl;
	}

	private static String addUriParameter(String url, String name, String value) {
		try {
			var uri = new URIBuilder(url).addParameter(name, value);
			return uri.toString();
		}
		catch (URISyntaxException ex) {
			throw new IllegalArgumentException("URL is invalid", ex);
		}
	}

	private static void setAuthnRequestConditions(Conditions conditions) {
		if (conditions != null) {
			conditions.setNotBefore(Instant.now());
			conditions.setNotOnOrAfter(Instant.now()
											  .plusSeconds(MAX_AUTHN_REQUEST_VALIDITY_SEC));
		}
	}

	private Map<String, SamlMockCpResponse> getEncodedResponseMap(String[] fileNames, String authnRequestId,
			String acsUrlFromInput, String relayState, String requestIssuer, boolean keepSampleUrls) {
		Map<String, SamlMockCpResponse> sampleMap = new TreeMap<>();
		if (fileNames != null && fileNames.length > 0) {
			Arrays.stream(fileNames)
					.forEach(fileName ->
							addResponseFromFile(
									authnRequestId, acsUrlFromInput, relayState, requestIssuer, keepSampleUrls, sampleMap,
									fileName)
					);
		}
		return sampleMap;
	}

	private void addResponseFromFile(String authnRequestId, String acsUrlFromInput, String relayState, String requestIssuer,
			boolean keepSampleUrls, Map<String, SamlMockCpResponse> sampleMap, String fileName) {
		try {
			// update response to be valid again
			var response = SamlIoUtil.unmarshallStatusResponse(getMockDirectoryPath(RESPONSE_DIRECTORY) + fileName);
			validateSAMLMockResponseSample(response, fileName);
			response.setIssueInstant(Instant.now());
			response.setInResponseTo(authnRequestId);

			var responseToEncrypt = SamlIoUtil.unmarshallStatusResponse(getMockDirectoryPath(RESPONSE_DIRECTORY) + fileName);
			var overrideDestination = keepSampleUrls ? response.getDestination() : null;
			var acsUrl = computeDestination(acsUrlFromInput, requestIssuer, overrideDestination, fileName);

			correctResponse(authnRequestId, fileName, response, acsUrl);
			correctResponse(authnRequestId, fileName, responseToEncrypt, acsUrl);

			// patch issuer references in response elements
			if (response instanceof Response authnResponse) {
				correctAssertion(authnRequestId, requestIssuer, acsUrl, keepSampleUrls, authnResponse);
				resignAllResponseElements(authnResponse);

				if (responseToEncrypt instanceof Response authnResponseToEncrypt) {
					correctAssertion(authnRequestId, requestIssuer, acsUrl, keepSampleUrls, authnResponseToEncrypt);

					reEncryptAssertions(authnResponseToEncrypt);
					resignStatusResponse(authnResponseToEncrypt, givenResponseCredential());
				}
			}
			else {
				resignStatusResponse(response, null);
			}

			// marshal
			var encodedPostMessage = SamlUtil.encode(response);
			var encodedArtifactMessage = SamlIoUtil.encodeSamlArtifactData(velocityEngine,
					artifactCacheService.getArtifactMap(), response, buildArtifactResolutionParameters(), relayState);
			var encodedEncryptedResponse = SamlUtil.encode(responseToEncrypt);

			// provide to client for selection, they work for 1-2 minutes
			var cpResponse = new SamlMockCpResponse();
			cpResponse.setSamlPostResponse(encodedPostMessage);
			cpResponse.setSamlArtifactResponse(encodedArtifactMessage);
			cpResponse.setRelayState(relayState);
			cpResponse.setAcsUrl(response.getDestination());
			cpResponse.setSamlEncryptedResponse(encodedEncryptedResponse);
			sampleMap.put(fileName, cpResponse);
		}
		catch (TrustBrokerException e) {
			log.error("Could not parse file={} message={}", fileName, e.getInternalMessage(), e);
		}
		catch (RuntimeException ex) {
			log.error("Could not parse file={} message={}", fileName, ex.getMessage(), ex);
		}
	}

	private ArtifactResolutionParameters buildArtifactResolutionParameters() {
		return ArtifactResolutionParameters.of(properties.getArtifactResolutionServiceUrl(),
				ENDPOINT_INDEX, properties.getArtifactResolutionIssuer());
	}

	private void reEncryptAssertions(Response authnResponseToEncrypt) {
		List<Assertion> assertions = new ArrayList<>(authnResponseToEncrypt.getAssertions());
		if (!CollectionUtils.isEmpty(assertions)) {
			authnResponseToEncrypt.getAssertions()
								  .clear();
			// re-encrypt all assertions
			for (Assertion assertion : assertions) {
				resignAssertion(assertion, givenResponseCredential());
				EncryptedAssertion encryptedAssertion = getEncryptedAssertion(assertion, properties);
				addEncryptedAssertionToResponse(encryptedAssertion, authnResponseToEncrypt);
			}
		}
	}

	private static void correctResponse(String authnRequestId, String fileName, StatusResponseType response, String acsUrl) {
		validateSAMLMockResponseSample(response, fileName);
		response.setIssueInstant(Instant.now());
		response.setInResponseTo(authnRequestId);
		response.setDestination(acsUrl);
	}

	private static void correctAssertion(String authnRequestId, String requestIssuer, String acsUrl, boolean keepSampleUrls,
			Response authnResponse) {
		List<Assertion> assertions = authnResponse.getAssertions();
		if (!CollectionUtils.isEmpty(assertions)) {
			// make all assertions valid
			for (Assertion assertion : assertions) {
				assertion.setIssueInstant(Instant.now());
				setSubjectConfirmation(authnRequestId, assertion, acsUrl);
				if (!keepSampleUrls) {
					setAudience(requestIssuer, authnResponse);
				}
				updateConditionTimestamps(assertion);
				setAuthnStatement(assertion);
			}
		}
		// use own signer to make valid for caller
	}

	private static void addEncryptedAssertionToResponse(EncryptedAssertion encryptedAssertion, Response response) {
		if (encryptedAssertion != null) {
			response.getEncryptedAssertions()
					.add(encryptedAssertion);
		}
	}

	private EncryptedAssertion getEncryptedAssertion(Assertion assertion, SamlMockProperties properties) {
		if (properties.getEncryptionKeystore() != null && properties.getEncryptionPassword() != null &&
				properties.getDataEncryptionAlgorithm() != null && assertion != null) {
			return EncryptionUtil.encryptAssertion(assertion, givenEncryptionCredential(),
					properties.getDataEncryptionAlgorithm(), properties.getKeyEncryptionAlgorithm(),
					Encrypter.KeyPlacement.valueOf(properties.getKeyPlacement()), "mock:issuer");
		}

		return null;
	}

	private void resignAllResponseElements(Response response) {
		var credential = givenResponseCredential();
		// sign a random assertion - XTB should handle it correctly in any case
		var idToSign = pickRandomSignedAssertionId(response.getAssertions());
		for (Assertion assertion : response.getAssertions()) {
			if (idToSign.equals(assertion.getID())) {
				resignAssertion(assertion, credential);
				log.debug("Assertion signature updated: {}", assertion.getID());
			}
			else if (assertion.isSigned()) {
				// clear (invalid) signature
				assertion.setSignature(null);
				log.debug("Assertion signature removed: {}", assertion.getID());
			}
		}
		resignStatusResponse(response, credential);
	}

	private String pickRandomSignedAssertionId(List<Assertion> assertions) {
		var signedAssertions = assertions.stream()
				.filter(assertion -> assertion.getSignature() != null)
				.toList();
		if (signedAssertions.isEmpty()) {
			return "";
		}
		return signedAssertions.get(random.nextInt(signedAssertions.size()))
							   .getID();
	}

	// set destination either from config (if set) or keep the one in the message
	private String computeDestination(String acsUrlFromInput, String requestIssuer, String overrideDestination,
			String fileName) {
		var acsUrl = acsUrlFromInput;
		var acsUrlSrc = "AuthnRequest message";
		var acsUrlFromConfig = properties.getSamlPostTargetUrl();
		if (acsUrlFromConfig != null) {
			acsUrl = acsUrlFromConfig;
			acsUrlSrc = SAML_POST_TARGET_URL + " config";
		}
		// the map is mainly for LogoutRequest, it does not override an existing ACS URL set above
		if (acsUrl == null) {
			var acsUrlMapFromConfig = properties.getSamlPostTargetUrlMap();
			if (acsUrlMapFromConfig != null) {
				var acsUrlFromMap = acsUrlMapFromConfig.get(requestIssuer);
				if (acsUrlFromMap != null) {
					acsUrl = acsUrlFromMap;
					acsUrlSrc = SAML_POST_TARGET_URL + "Map config";
				}
			}
		}
		if (overrideDestination != null) {
			acsUrl = overrideDestination;
			acsUrlSrc = "Sample destination";
		}
		log.info("Patching destination in sample {} using acsUrl from {} resulting in {}", fileName, acsUrlSrc, acsUrl);
		return acsUrl;
	}

	// Mock should not check response validity as we want to be able to produce anything to send to XTB
	private static void validateSAMLMockResponseSample(StatusResponseType response, String s) {
		if (response == null) {
			throw new TechnicalException(String.format("Response is null in file with name=%s", s));
		}
	}

	private static void setAuthnStatement(Assertion assertion) {
		assertion.getAuthnStatements()
				 .get(0)
				 .setAuthnInstant(Instant.now());
		if (assertion.getAuthnStatements()
					 .get(0)
					 .getSessionNotOnOrAfter() != null) {
			assertion.getAuthnStatements()
					 .get(0)
					 .setSessionNotOnOrAfter(Instant.now()
													.plusSeconds(MAX_ASSERTION_VALIDITY_SEC));
		}
	}

	private static void updateConditionTimestamps(Assertion assertion) {
		if (assertion.getConditions() != null) {
			if (assertion.getConditions()
						 .getNotBefore() != null) {
				assertion.getConditions()
						 .setNotBefore(Instant.now());
			}
			if (assertion.getConditions()
						 .getNotOnOrAfter() != null) {
				assertion.getConditions()
						 .setNotOnOrAfter(Instant.now()
												 .plusSeconds(MAX_ASSERTION_VALIDITY_SEC));
			}
		}
	}

	private static void setSubjectConfirmation(String authnRequestId, Assertion assertion, String issuer) {
		if (assertion == null) {
			return;
		}
		var subject = assertion.getSubject();
		List<SubjectConfirmation> subjectConfirmations = subject.getSubjectConfirmations();
		if (!CollectionUtils.isEmpty(subjectConfirmations)) {
			var subjectConfirmationData = subjectConfirmations.get(0)
															  .getSubjectConfirmationData();
			if (subjectConfirmationData != null) {
				if (subjectConfirmationData.getNotBefore() != null) {
					subjectConfirmationData.setNotBefore(Instant.now());
				}
				subjectConfirmationData.setInResponseTo(authnRequestId);
				if (subjectConfirmationData.getNotOnOrAfter() != null) {
					subjectConfirmationData.setNotOnOrAfter(Instant.now()
																   .plusSeconds(MAX_ASSERTION_VALIDITY_SEC));
				}
			}
			if (subjectConfirmationData != null && subjectConfirmationData.getRecipient() != null) {
				log.info("Updating SubjectConfirmation.Recipient from '{}' to '{}'",
						subjectConfirmationData.getRecipient(), issuer);
				subjectConfirmationData.setRecipient(issuer);
			}
		}
	}

	private static void setAudience(String audienceUri, Response authnResponse) {
		var assertions = authnResponse.getAssertions();
		if (CollectionUtils.isEmpty(assertions)) {
			return;
		}
		var conditions = assertions.get(0)
								   .getConditions();
		if (conditions == null) {
			return;
		}
		List<AudienceRestriction> audienceRestrictions = conditions.getAudienceRestrictions();
		if (!CollectionUtils.isEmpty(audienceRestrictions)) {
			List<Audience> audiences = audienceRestrictions.get(0)
														   .getAudiences();
			if (!audiences.isEmpty() && audienceUri != null) {
				log.info("Updating subjectConfirmationData.AudienceURI from '{}' to '{}'", audiences.get(0)
																									.getURI(),
						audienceUri);
				audiences.clear();
				var audience = OpenSamlUtil.buildSamlObject(Audience.class);
				audience.setURI(audienceUri);
				audiences.add(audience);
			}
		}
	}

	private static String[] listDirectoryContent(String directory) {
		var dir = new File(directory);
		var files = dir.list();
		if (files != null) {
			Arrays.sort(files);
		}
		if (log.isDebugEnabled()) {
			log.debug("directory={} contains files={}", dir.getAbsolutePath(),
					files != null ? Arrays.asList(files) : null);
		}
		return files;
	}

	private void resignAssertion(Assertion assertion, Credential credential) {
		if (assertion.getSignature() != null) {
			var newSignature = SamlFactory.prepareSignableObject(
					assertion, credential, null, null, null);
			SamlUtil.signSamlObject(assertion, newSignature, properties.getSkinnyAssertionNamespaces());
			if (log.isTraceEnabled()) {
				log.trace("Response assertion signed: {}", OpenSamlUtil.samlObjectToString(assertion));
			}
		}
	}

	private void resignStatusResponse(StatusResponseType response, Credential credential) {
		if (response.getSignature() != null) {
			if (credential == null) {
				credential = givenResponseCredential();
			}
			var newSignature = SamlFactory.prepareSignableObject(
					response, credential, null, null, null);
			SamlUtil.signSamlObject(response, newSignature);
			if (log.isTraceEnabled()) {
				log.trace("Response signed: {}", OpenSamlUtil.samlObjectToString(response, false, true));
			}
		}
	}

	private void resignSamlObject(SignableSAMLObject request) {
		var newSignature = SamlFactory.prepareSignableObject(
				request, givenAuthnRequestCredential(), null, null, null);
		SamlUtil.signSamlObject(request, newSignature);
		if (log.isTraceEnabled()) {
			log.trace("Request {} signed: {}", request.getClass()
													  .getSimpleName(),
					OpenSamlUtil.samlObjectToString(request, false, true));
		}
	}

	private Credential givenAuthnRequestCredential() {
		// key shall be stored along cert
		return CredentialReader.createCredential(
				getSpSignerKeystorePath(),
				null,
				properties.getSpSignerPassword(),
				properties.getSpSignerAlias(),
				getSpSignerKeystorePath()); // key shall be stored along cert
	}

	private Credential givenResponseCredential() {
		// key shall be stored along cert
		return CredentialReader.createCredential(
				getIdpSignerKeystorePath(),
				null,
				properties.getIdpSignerPassword(),
				properties.getIdpSignerAlias(),
				getIdpSignerKeystorePath()); // key shall be stored along cert
	}

	private Credential givenEncryptionCredential() {
		// key shall be stored along cert
		return CredentialReader.createCredential(
				getEncryptionKeystorePath(),
				null,
				properties.getEncryptionPassword(),
				properties.getEncryptionAlias(),
				getEncryptionKeystorePath());
	}

	private MessageContext decodeSamlMessage(HttpServletRequest request, ArtifactPeer peer) {
		if (OpenSamlUtil.isSamlArtifactRequest(request)) {
			if (log.isInfoEnabled()) {
				log.info("Decoding received SAML Artifact={} peer={}",
						StringUtil.clean(SamlIoUtil.getSamlArtifactDataFromHttpProtocol(request)), peer);
			}
			// credential is always same side for SamlMock as the same issuerId is used for both sides
			var credential = properties.isArtifactResolutionIssuerIsRp() ?
					givenAuthnRequestCredential() : givenResponseCredential();
			var signatureParameters = Optional.of(SignatureParameters.builder()
																	 .credential(credential)
																	 .build());
			return OpenSamlUtil.decodeSamlArtifactMessage(request, properties.getArtifactResolutionIssuer(),
					peer, signatureParameters, SignatureValidationParameters.of(false, Collections.emptyList()),
					Optional.empty());
		}
		else {
			log.info("Decoding received SAML message");
			return OpenSamlUtil.decodeSamlPostMessage(request);
		}
	}

}
