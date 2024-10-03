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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.soap.wsaddressing.Action;
import org.opensaml.soap.wsaddressing.Address;
import org.opensaml.soap.wsaddressing.MessageID;
import org.opensaml.soap.wsaddressing.ReplyTo;
import org.opensaml.soap.wsaddressing.To;
import org.opensaml.soap.wstrust.WSTrustConstants;
import org.slf4j.LoggerFactory;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.saml.util.AssertionValidator;
import swiss.trustbroker.test.util.MemoryAppender;
import swiss.trustbroker.wstrust.dto.SoapMessageHeader;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.STRICT_STUBS)
class WsHeaderValidatorTest {

	private static final String TEST_AUDIENCE = "http://localhost:8080";

	private static final String TEST_TO = WsHeaderValidatorTest.class.getName();

	private MemoryAppender memoryAppender;

	private TrustBrokerProperties properties;

	private void enableDebug(Class clazz, MemoryAppender memoryAppender) {
		Logger logger = (Logger) LoggerFactory.getLogger(clazz);
		logger.setLevel(Level.DEBUG);
		logger.addAppender(memoryAppender);
	}

	@BeforeEach
	public void setup() {
		// catch log output of interest
		memoryAppender = new MemoryAppender();
		memoryAppender.setContext((LoggerContext) LoggerFactory.getILoggerFactory());
		enableDebug(AssertionValidator.class, memoryAppender);
		enableDebug(WsHeaderValidator.class, memoryAppender);
		memoryAppender.start();

		SamlInitializer.initSamlSubSystem();

		// security checks enabled, issue must be set
		properties = new TrustBrokerProperties();
		properties.setIssuer(TEST_AUDIENCE);
	}

	@AfterEach
	public void cleanUp() {
		memoryAppender.reset();
		memoryAppender.stop();
	}

	@Test
	void validateHeaderElementsMissingHeaderTest() {
		var ex = assertThrows(RequestDeniedException.class, () -> {
			WsHeaderValidator.validateHeaderElements(null, "validateHeaderElementsMissingHeaderTest-Issuer");
		});
		assertException("SOAP request header missing", ex);
	}

	@Test
	void validateHeaderElementsNoActionTest() {
		SoapMessageHeader requestHeader = givenRequestHeader();
		requestHeader.setAction(null);
		var ex = assertThrows(RequestDeniedException.class, () -> {
			WsHeaderValidator.validateHeaderElements(requestHeader, "");
		});
		assertException("Action missing or invalid in SOAP header", ex);
	}

	@Test
	void validateHeaderElementsInvalidActionTest() {
		SoapMessageHeader requestHeader = givenRequestHeader();
		requestHeader.getAction().setURI("http://invalidaction");
		var ex = assertThrows(RequestDeniedException.class, () -> {
			WsHeaderValidator.validateHeaderElements(requestHeader, "");
		});
		assertException("Action missing or invalid in SOAP header", ex);
	}

	@Test
	void validateHeaderElementsNullMessageIdTest() {
		SoapMessageHeader requestHeader = givenRequestHeader();
		requestHeader.setMessageId(null);
		var ex = assertThrows(RequestDeniedException.class, () -> {
			WsHeaderValidator.validateHeaderElements(requestHeader, "validateHeaderElementsNullMessageIdTest-Issuer");
		});
		assertException("MessageId missing in SOAP header", ex);
	}

	@Test
	void validateHeaderElementsNoMessageIdTest() {
		SoapMessageHeader requestHeader = givenRequestHeader();
		requestHeader.setMessageId(null);
		var ex = assertThrows(RequestDeniedException.class, () -> {
			WsHeaderValidator.validateHeaderElements(requestHeader, "validateHeaderElementsNoMessageIdTest-Issuer");
		});
		assertException("MessageId missing in SOAP header", ex);
	}

	@Test
	void validateHeaderElementsNullReplayToTest() {
		SoapMessageHeader requestHeader = givenRequestHeader();
		requestHeader.setReplyTo(null);
		var ex = assertThrows(RequestDeniedException.class, () -> {
			WsHeaderValidator.validateHeaderElements(requestHeader, "validateHeaderElementsNullReplayToTest-Issuer");
		});
		assertException("ReplyTo missing in SOAP header", ex);
	}

	@Test
	void validateHeaderElementsNullAddressTest() {
		SoapMessageHeader requestHeader = givenRequestHeader();
		requestHeader.getReplyTo().setAddress(null);
		var ex = assertThrows(RequestDeniedException.class, () -> {
			WsHeaderValidator.validateHeaderElements(requestHeader, "");
		});
		assertException("Address missing or invalid in ReplyTo SOAP header", ex);
	}

	@Test
	void validateHeaderElementsNoAddressTest() {
		SoapMessageHeader requestHeader = givenRequestHeader();
		requestHeader.getReplyTo().getAddress().setURI(Address.NONE);
		var ex = assertThrows(RequestDeniedException.class, () -> {
			WsHeaderValidator.validateHeaderElements(requestHeader, "");
		});
		assertException("Address missing or invalid in ReplyTo SOAP header", ex);
	}

	@Test
	void validateHeaderElementsInvalidAddressTest() {
		SoapMessageHeader requestHeader = givenRequestHeader();
		requestHeader.getReplyTo().getAddress().setURI("http://randomaddress");
		var ex = assertThrows(RequestDeniedException.class, () -> {
			WsHeaderValidator.validateHeaderElements(requestHeader, "");
		});
		assertException("Address missing or invalid in ReplyTo SOAP header", ex);
	}

	@Test
	void validateHeaderElementsValidTest() {
		SoapMessageHeader requestHeader = givenRequestHeader();
		assertDoesNotThrow(() -> {
			WsHeaderValidator.validateHeaderElements(requestHeader, TEST_TO);
		});
	}

	@Test
	void validateAssertionNoAssertionTest() {
		assertThrows(RequestDeniedException.class, () -> {
			WsHeaderValidator.validateAssertion(null, properties);
		});
	}

	@Test
	void validateAssertionNoAssertionIdTest() {
		Assertion assertion = givenAssertion("NameID", TEST_AUDIENCE, SubjectConfirmation.METHOD_HOLDER_OF_KEY);
		assertion.setID("");
		var ex = assertThrows(RequestDeniedException.class, () -> {
			WsHeaderValidator.validateAssertion(assertion, properties);
		});
		assertException("ID missing", ex);
	}

	@Test
	void validateAssertionNullAssertionIdTest() {
		Assertion assertion = givenAssertion("NameID", TEST_AUDIENCE, SubjectConfirmation.METHOD_HOLDER_OF_KEY);
		assertion.setID(null);
		var ex = assertThrows(RequestDeniedException.class, () -> {
			WsHeaderValidator.validateAssertion(assertion, properties);
		});
		assertException("ID missing", ex);
	}

	@Test
	void validateAssertionNullSubjectTest() {
		Assertion assertion = givenAssertion("NameID", TEST_AUDIENCE, SubjectConfirmation.METHOD_HOLDER_OF_KEY);
		assertion.setSubject(null);
		var ex = assertThrows(RequestDeniedException.class, () -> {
			WsHeaderValidator.validateAssertion(assertion, properties);
		});
		assertException("Subject missing", ex);
	}

	@Test
	void validateAssertionNullNameIdTest() {
		Assertion assertion = givenAssertion(null, TEST_AUDIENCE, SubjectConfirmation.METHOD_HOLDER_OF_KEY);
		var ex = assertThrows(RequestDeniedException.class, () -> {
			WsHeaderValidator.validateAssertion(assertion, properties);
		});
		assertException("NameId missing", ex);
	}

	@Test
	void validateAssertionNoNameIdTest() {
		Assertion assertion = givenAssertion("", TEST_AUDIENCE, SubjectConfirmation.METHOD_HOLDER_OF_KEY);
		var ex = assertThrows(RequestDeniedException.class, () -> {
			WsHeaderValidator.validateAssertion(assertion, properties);
		});
		assertException("NameId missing", ex);
	}

	@Test
	void validateAssertionEmptySubjectConfirmationsTest() {
		Assertion assertion = givenAssertion("NameID", TEST_AUDIENCE, SubjectConfirmation.METHOD_HOLDER_OF_KEY);
		assertion.getSubject().getSubjectConfirmations().clear();
		var ex = assertThrows(RequestDeniedException.class, () -> {
			WsHeaderValidator.validateAssertion(assertion, properties);
		});
		assertException("SubjectConfirmations missing", ex);
	}

	@Test
	void validateAssertionWrongMethodInSubjectConfirmationTest() {
		Assertion assertion = givenAssertion("NameID", TEST_AUDIENCE, "Invalid-Method");
		var ex = assertThrows(RequestDeniedException.class, () -> {
			WsHeaderValidator.validateAssertion(assertion, properties);
		});
		assertException("SubjectConfirmation.Method missing", ex);
	}

	@Test
	void validateAssertionNullIssuerTest() {
		Assertion assertion = givenAssertion("NameID", TEST_AUDIENCE, SubjectConfirmation.METHOD_HOLDER_OF_KEY);
		assertion.setIssuer(null); // empty
		var ex = assertThrows(RequestDeniedException.class, () -> {
			WsHeaderValidator.validateAssertion(assertion, properties);
		});
		assertException("Assertion.Issuer missing", ex);
	}

	@Test
	void validateAssertionEmptyIssuerTest() {
		Assertion assertion = givenAssertion("NameID", TEST_AUDIENCE, SubjectConfirmation.METHOD_HOLDER_OF_KEY);
		assertion.getIssuer().setValue(""); // empty
		var ex = assertThrows(RequestDeniedException.class, () -> {
			WsHeaderValidator.validateAssertion(assertion, properties);
		});
		assertException("Assertion.Issuer missing", ex);
	}

	@Test // https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf Page 24, Line 976
	void validateAssertionInvalidAudienceRestrictionTest() {
		Assertion assertion = givenAssertion("NameID", "Invalid-Audience", SubjectConfirmation.METHOD_HOLDER_OF_KEY);
		var ex = assertThrows(RequestDeniedException.class, () -> {
			WsHeaderValidator.validateAssertion(assertion, properties);
		});
		assertException("Audience missing or invalid", ex);
	}

	@Test // https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf Page 24, Line 976
	void validateAssertionValidAudienceRestrictionTest() {
		Assertion assertion = givenAssertion("NameID", TEST_AUDIENCE, SubjectConfirmation.METHOD_HOLDER_OF_KEY);
		WsHeaderValidator.validateAssertion(assertion, properties);
	}

	@Test
	void validateAssertionInvalidAudiencesTest() {
		Assertion assertion = givenAssertion("NameID", "invalidAudience", SubjectConfirmation.METHOD_HOLDER_OF_KEY);
		var ex = assertThrows(RequestDeniedException.class, () -> {
			WsHeaderValidator.validateAssertion(assertion, properties);
		});
		assertException("Audience missing or invalid", ex);
	}

	@Test
	void validateAssertionNullAttributeStatementsTest() {
		Assertion assertion = givenAssertion("NameID", TEST_AUDIENCE, SubjectConfirmation.METHOD_HOLDER_OF_KEY);
		assertion.getAttributeStatements().clear();
		WsHeaderValidator.validateAssertion(assertion, properties);
		assertLog("AttributeStatements missing", Level.INFO);
	}

	@Test
	void validateAssertionEmptyAttributeStatementsTest() {
		Assertion assertion = givenAssertion("NameID", TEST_AUDIENCE, SubjectConfirmation.METHOD_HOLDER_OF_KEY);
		assertion.getAttributeStatements().clear();
		WsHeaderValidator.validateAssertion(assertion, properties);
		assertLog("AttributeStatements missing", Level.INFO);
	}

	@Test
	void validateAssertionValidTest() {
		Assertion assertion = givenAssertion("NameID", TEST_AUDIENCE, SubjectConfirmation.METHOD_HOLDER_OF_KEY);
		assertDoesNotThrow(() -> {
			WsHeaderValidator.validateAssertion(assertion, properties);
		});
	}

	private List<AttributeStatement> giveAttributeStatements() {
		List<AttributeStatement> attributeStatements = new ArrayList<>();
		AttributeStatement attributeStatement = OpenSamlUtil.buildSamlObject(AttributeStatement.class);
		attributeStatements.add(attributeStatement);
		return attributeStatements;
	}

	private List<Audience> givenAudiences(String audienceUrl) {
		List<Audience> audiences = new ArrayList<>();
		Audience audience = OpenSamlUtil.buildSamlObject(Audience.class);
		audience.setURI(audienceUrl);
		audiences.add(audience);
		return audiences;
	}

	private List<AudienceRestriction> givenAudienceRestrictions() {
		List<AudienceRestriction> audienceRestrictions = new ArrayList<>();
		return audienceRestrictions;
	}

	private Conditions givenConditions() {
		Conditions conditions = OpenSamlUtil.buildSamlObject(Conditions.class);
		return conditions;
	}

	private SubjectConfirmation givenSubjectConfirmation(String method) {
		SubjectConfirmation subjectConfirmation = OpenSamlUtil.buildSamlObject(SubjectConfirmation.class);
		subjectConfirmation.setMethod(method);
		return subjectConfirmation;
	}

	private List<SubjectConfirmation> givenSubjectConfirmations() {
		List<SubjectConfirmation> subjectConfirmations = new ArrayList<>();
		return subjectConfirmations;
	}

	private NameID givenNameId(String nameIdValue) {
		NameID nameID = OpenSamlUtil.buildSamlObject(NameID.class);
		nameID.setValue(nameIdValue);
		return nameID;
	}

	private Subject givenSubject() {
		return OpenSamlUtil.buildSamlObject(Subject.class);
	}

	private Assertion givenAssertion(String nameId, String audience, String subjectConfirmation) {
		Assertion assertion = OpenSamlUtil.buildAssertionObject();
		assertion.setIssueInstant(Instant.now());
		// ID
		assertion.setID(UUID.randomUUID().toString());
		// issuer
		assertion.setIssuer(OpenSamlUtil.buildSamlObject(Issuer.class));
		assertion.getIssuer().setValue(TEST_AUDIENCE);
		// subject
		assertion.setSubject(givenSubjectNameIdAndConfirmations(givenSubject(), givenNameId(nameId),
				givenSubjectConfirmations(), givenSubjectConfirmation(subjectConfirmation)));
		// audience
		assertion.setConditions(givenAudienceOfConditions(givenConditions(),
				givenAudienceRestrictions(), givenAudiences(audience)));
		// attributes
		assertion.getAttributeStatements().addAll(giveAttributeStatements());
		return assertion;
	}

	private Conditions givenAudienceOfConditions(Conditions conditions, List<AudienceRestriction> audienceRestrictions,
			List<Audience> audiences) {
		if (audienceRestrictions == null) {
			return conditions;
		}

		conditions.getAudienceRestrictions().addAll(audienceRestrictions);
		if (audiences != null) {
			conditions.getAudienceRestrictions().add(givenAudienceRestWithAudience(audiences));
		}

		return conditions;
	}

	private AudienceRestriction givenAudienceRestWithAudience(List<Audience> audiences) {
		AudienceRestriction audienceRestriction = OpenSamlUtil.buildSamlObject(AudienceRestriction.class);
		audienceRestriction.getAudiences().addAll(audiences);
		return audienceRestriction;
	}

	private Subject givenSubjectNameIdAndConfirmations(Subject subject, NameID nameID,
			List<SubjectConfirmation> subjectConfirmations, SubjectConfirmation subjectConfirmation) {
		if (subject == null) {
			return subject;
		}
		subject.setNameID(nameID);
		if (subjectConfirmations == null) {
			return subject;
		}
		subjectConfirmations.add(subjectConfirmation);
		subject.getSubjectConfirmations().addAll(subjectConfirmations);
		return subject;
	}

	private To givenTo(String toValue) {
		To to = (To) XMLObjectSupport.buildXMLObject(To.ELEMENT_NAME);
		to.setURI(toValue);
		return to;
	}

	private Address givenAddress(String addressValue) {
		Address address = (Address) XMLObjectSupport.buildXMLObject(Address.ELEMENT_NAME);
		address.setURI(addressValue);
		return address;
	}

	private ReplyTo givenReplyTo() {
		return (ReplyTo) XMLObjectSupport.buildXMLObject(ReplyTo.ELEMENT_NAME);
	}

	private MessageID givenMessageId(String messageIdValue) {
		MessageID messageID = (MessageID) XMLObjectSupport.buildXMLObject(MessageID.ELEMENT_NAME);
		messageID.setURI(messageIdValue);
		return messageID;
	}

	private Action givenAction(String actionValue) {
		Action action = (Action) XMLObjectSupport.buildXMLObject(Action.ELEMENT_NAME);
		action.setURI(actionValue);
		return action;
	}

	private SoapMessageHeader givenRequestHeader() {
		SoapMessageHeader requestHeader = new SoapMessageHeader();
		requestHeader.setAction(givenAction(WSTrustConstants.WSA_ACTION_RST_ISSUE));
		requestHeader.setMessageId(givenMessageId(UUID.randomUUID().toString()));
		requestHeader.setReplyTo(givenReplyToAddress(givenReplyTo(), givenAddress(Address.ANONYMOUS)));
		requestHeader.setTo(givenTo(TEST_TO));
		return requestHeader;
	}

	private ReplyTo givenReplyToAddress(ReplyTo replyTo, Address address) {
		if (replyTo == null) {
			return null;
		}
		replyTo.setAddress(address);
		return replyTo;
	}

	private void assertLog(String expectedString, Level level) {
		assertTrue(memoryAppender.contains(expectedString, level),
				"'" + expectedString + "' not found in: " + getLastLogLine());
	}

	private void assertException(String expectedString, Exception ex) {
		assertTrue(((RequestDeniedException)ex).getInternalMessage().contains(expectedString),
				"'" + expectedString + "' not found in: " + ex.getMessage());
	}

	private String getLastLogLine() {
		List<ILoggingEvent> list = memoryAppender.getLoggedEvents();
		if (list.size() >0) {
			return list.get(list.size() - 1).getFormattedMessage();
		}
		return "empty log";
	}

}
