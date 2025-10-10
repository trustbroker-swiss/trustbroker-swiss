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

package swiss.trustbroker.wstrust.validator;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import javax.xml.namespace.QName;

import lombok.extern.slf4j.Slf4j;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.soap.wssecurity.BinarySecurityToken;
import org.opensaml.soap.wstrust.RenewTarget;
import org.opensaml.soap.wstrust.RequestSecurityToken;
import org.opensaml.soap.wstrust.RequestType;
import org.opensaml.soap.wstrust.WSTrustConstants;
import org.springframework.stereotype.Component;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.CredentialReader;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.util.WSSConstants;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.SsoSessionIdPolicy;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.saml.util.AssertionValidator;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.sessioncache.service.StateCacheService;
import swiss.trustbroker.util.CertificateUtil;
import swiss.trustbroker.wstrust.dto.WsTrustValidationResult;

/**
 * Validator for WS-Trust RENEW requests.
 */
@Component
@Slf4j
public class WsTrustRenewValidator extends WsTrustBaseValidator {

	private final StateCacheService stateCacheService;

	private final Optional<List<Credential>> signerTrustCredentials;

	public WsTrustRenewValidator(
			TrustBrokerProperties trustBrokerProperties, RelyingPartySetupService relyingPartySetupService, Clock clock,
			StateCacheService stateCacheService) {
		super(trustBrokerProperties, relyingPartySetupService, clock);
		this.stateCacheService = stateCacheService;
		if (enabled()) {
			this.signerTrustCredentials = Optional.of(CertificateUtil.getXtbSignerCredentials(trustBrokerProperties));
		}
		else {
			this.signerTrustCredentials = Optional.empty();
		}
	}

	@Override
	public boolean applies(RequestType requestType) {
		if (!RequestType.RENEW.equals(requestType.getURI())) {
			return false;
		}
		if (!enabled()) {
			log.error("RequestType in RSTR requestType='{}' but RENEW disabled in configuration", requestType.getURI());
			return false;
		}
		return true;
	}

	private boolean enabled() {
		var properties = getTrustBrokerProperties();
		return properties.getWstrust() != null && properties.getWstrust().isRenewEnabled();
	}

	@Override
	public WsTrustValidationResult validate(RequestSecurityToken requestSecurityToken, Assertion headerAssertion,
						   BinarySecurityToken securityToken) {
		if (headerAssertion != null) {
			// not required for RENEW, but validate if present
			// (e.g. client using same wss4j configuration for ISSUE and RENEW)
			log.info("RSTR with requestType='{}' validating ignored header assertionID='{}'",
					RequestType.RENEW, headerAssertion.getID());
			validateAssertion(headerAssertion, null, Optional.empty());
		}
		var childObjects = requestSecurityToken.getUnknownXMLObjects();
		log.debug("RSTR RENEW request - assertion is in RenewTarget");
		var assertion = extractRenewTargetAssertion(childObjects);
		var relyingParty = getRecipientRelyingParty(assertion);
		var session = findValidSsoSession(assertion);
		String expectedSessionId = null;
		if (session.isPresent()) {
			expectedSessionId = session.get().getSsoSessionId();
		}
		var expectedValues = AssertionValidator.ExpectedAssertionValues.builder()
																	   .expectedIssuer(getTrustBrokerProperties().getIssuer())
																	   .expectedAudience(relyingParty.getId())
																	   .expectedSessionIndex(expectedSessionId)
																	   .expectedRecipient(relyingParty.getId())
																	   .renew(true)
																	   .build();
		validateAssertion(assertion, expectedValues, signerTrustCredentials);
		validateSecurityToken(securityToken, relyingParty);
		return new WsTrustValidationResult(assertion, false, relyingParty.getId());
	}

	private static Assertion extractRenewTargetAssertion(List<XMLObject> childObjects) {
		var renewTargetQname = new QName(WSTrustConstants.WST_NS, RenewTarget.ELEMENT_LOCAL_NAME);
		RenewTarget renewTarget = OpenSamlUtil.findChildObjectByQname(childObjects, renewTargetQname);
		var renewTargetObject = renewTarget != null ? renewTarget.getUnknownXMLObject() : null;
		if (!(renewTargetObject instanceof Assertion renewAssertion)) {
			throw new RequestDeniedException(String.format(
					"RSTR with header requestType='%s' renewTarget='%s' has wrong type, expected Assertion",
					RequestType.RENEW, renewTargetObject != null ? renewTargetObject.getClass().getName() : null));
		}
		return renewAssertion;
	}

	Optional<StateData> findValidSsoSession(Assertion assertion) {
		List<String> ssoSessionIds = extractSsoSessionIds(assertion);
		List<StateData> sessions = ssoSessionIds.stream()
												.map(findSsoSession())
												.filter(Optional::isPresent)
												.map(Optional::get)
												.toList();
		if (sessions.isEmpty()) {
			if (getTrustBrokerProperties().getWstrust().isRenewRequiresSsoSession()) {
				throw new RequestDeniedException(String.format(
						"RSTR with requestType='%s' - no valid SSO session with ssoSessionIds=%s",
						RequestType.RENEW, ssoSessionIds));
			}
			log.debug("RSTR with requestType='{}' - no valid SSO session with ssoSessionIds={}", RequestType.RENEW, ssoSessionIds);
			return Optional.empty();
		}
		// usually there is just a single AuthnStatement and this could not happen
		if (sessions.size() > 1 && log.isErrorEnabled()) {
			List<String> foundSessionIds = sessions.stream().map(StateData::getSsoSessionId).toList();
			log.error("Multiple valid SSO session with ssoSessionIds={} foundSessionIds={}", ssoSessionIds, foundSessionIds);
		}
		var stateData = sessions.get(0);
		log.info("Found valid stateId={} ssoSessionId={}", stateData.getId(), stateData.getSsoSessionId());
		return Optional.of(stateData);
	}

	private Function<String, Optional<StateData>> findSsoSession() {
		return ssoSessionId -> stateCacheService.findBySsoSessionId(ssoSessionId, WsTrustRenewValidator.class.getName());
	}

	private static List<String> extractSsoSessionIds(Assertion assertion) {
		return assertion.getAuthnStatements()
						.stream()
						.map(AuthnStatement::getSessionIndex)
						.filter(SsoSessionIdPolicy::isSsoSession)
						.toList();
	}

	void validateSecurityToken(BinarySecurityToken securityToken, RelyingParty relyingParty) {
		if (securityToken == null) {
			if (getTrustBrokerProperties().getWstrust().isRenewRequiresSecurityToken()) {
				throw new RequestDeniedException(String.format(
						"RSTR with requestType='%s' missing header security token", RequestType.RENEW));
			}
			log.debug("RSTR with requestType='{}' missing header security token", RequestType.RENEW);
			return;
		}
		if (!WSSConstants.ENCODING_BASE64_BINARY.equals(securityToken.getEncodingType())) {
			throw new RequestDeniedException(String.format(
					"RSTR with requestType='%s' contains security token with encodingType='%s' expectedEncodingType=%s",
					RequestType.RENEW, securityToken.getEncodingType(), WSSConstants.ENCODING_BASE64_BINARY));
		}
		if (!WSSConstants.VALUE_X509_V3.equals(securityToken.getValueType())) {
			throw new RequestDeniedException(String.format(
					"RSTR with requestType='%s' contains security token with valueType='%s' expectedValueType=%s",
					RequestType.RENEW, securityToken.getValueType(), WSSConstants.VALUE_X509_V3));
		}
		validateCertificate(securityToken, relyingParty);
	}

	private static void validateCertificate(BinarySecurityToken securityToken, RelyingParty relyingParty) {
			log.debug("Received tokenType={} securityToken={}", securityToken.getValueType(), securityToken.getValue());
			if (securityToken.getValue() == null) {
				throw new RequestDeniedException(String.format(
						"RSTR with requestType='%s' contains security token with valueType='%s' without value",
						RequestType.RENEW, securityToken.getValueType()));

			}
			X509Credential tokenCredential;
			try (var inputStream = new ByteArrayInputStream(securityToken.getValue().getBytes(StandardCharsets.UTF_8))) {
				// returned value is always an X509Credential
				tokenCredential = (X509Credential) CredentialReader.getPemCredential(inputStream, WSSConstants.VALUE_X509_V3);
			}
			catch (TechnicalException | IOException ex) {
				throw new RequestDeniedException(String.format(
						"RSTR with requestType='%s' contains security token with valueType='%s' - could not parse certificate",
						RequestType.RENEW, securityToken.getValueType()), ex);
			}
			log.debug("Received tokenType={} certificateType={}", securityToken.getValueType(),
					tokenCredential.getCredentialType());
			for (var credential : relyingParty.getRpTrustCredentials()) {
				log.debug("Checking received token against credentialType={}", credential.getCredentialType());
				if (credential instanceof X509Credential x509Credential) {
					if (x509Credential.getEntityCertificate().equals(tokenCredential.getEntityCertificate())) {
						log.info("Received tokenType={} certificateType={} matching certificate={} of rpIssuerId={}",
								securityToken.getValueType(), tokenCredential.getCredentialType(),
								x509Credential.getEntityId(), relyingParty.getId());
						return;
					}
				}
				else {
					// should not happen as they are produced with CredentialReader
					log.error("Unexpected trustCredentialType={} of rpIssuerId={}",
							credential.getCredentialType(), relyingParty.getId());
				}
			}
			throw new RequestDeniedException(String.format(
					"RSTR with requestType='%s' contains security token with valueType='%s' not matching any of the trust credentials of rpIssuerId=%s",
					RequestType.RENEW, securityToken.getValueType(), relyingParty.getId()));
	}
}
