/*
 * Derivative work of original class from org.springframework.security:spring-security-saml2-service-provider 6.2.4:
 * org.springframework.security.saml2.provider.service.web.authentication.OpenSamlAuthenticationRequestResolver
 *
 * https://docs.spring.io/spring-security
 *
 * Changes: search for opensaml5. Additional changes to resolve source code scanner issuer. See also:
 *
 * https://github.com/spring-projects/spring-security/issues/11658
 *
 * Copyright 2002-2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package swiss.trustbroker.oidc.opensaml5;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;
import java.util.function.BiConsumer;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.xml.SerializeSupport;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnRequestMarshaller;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2PostAuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationPlaceholderResolvers;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationPlaceholderResolvers.UriResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.w3c.dom.Element;
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.common.tracing.TraceSupport;

/**
 * For internal use only. Intended for consolidating common behavior related to minting a
 * SAML 2.0 Authn Request.
 */
@Slf4j
@SuppressWarnings({"java:S1611", "unchecked"}) // opensaml5: ignore code formatting and complexity issues in copied code
class OpenSamlAuthenticationRequestResolver {

	static {
		SamlInitializer.initSamlSubSystem(); // opensaml5: changed from OpenSamlInitializationService
	}

	private final RelyingPartyRegistrationResolver relyingPartyRegistrationResolver;

	private final AuthnRequestBuilder authnRequestBuilder;

	private final AuthnRequestMarshaller marshaller;

	private final IssuerBuilder issuerBuilder;

	private final NameIDBuilder nameIdBuilder;

	private final NameIDPolicyBuilder nameIdPolicyBuilder;

	private RequestMatcher requestMatcher = new AntPathRequestMatcher(
			Saml2AuthenticationRequestResolver.DEFAULT_AUTHENTICATION_REQUEST_URI);

	private Converter<HttpServletRequest, String> relayStateResolver = (request) -> UUID.randomUUID().toString();

	/**
	 * Construct a {@link OpenSamlAuthenticationRequestResolver} using the provided
	 * parameters
	 * @param relyingPartyRegistrationResolver a strategy for resolving the
	 * {@link RelyingPartyRegistration} from the {@link HttpServletRequest}
	 */
	OpenSamlAuthenticationRequestResolver(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
		Assert.notNull(relyingPartyRegistrationResolver, "relyingPartyRegistrationResolver cannot be null");
		this.relyingPartyRegistrationResolver = relyingPartyRegistrationResolver;
		XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
		this.marshaller = (AuthnRequestMarshaller) registry.getMarshallerFactory()
			.getMarshaller(AuthnRequest.DEFAULT_ELEMENT_NAME);
		Assert.notNull(this.marshaller, "authnRequestMarshaller must be configured in OpenSAML");
		this.authnRequestBuilder = (AuthnRequestBuilder) XMLObjectProviderRegistrySupport.getBuilderFactory()
			.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
		Assert.notNull(this.authnRequestBuilder, "authnRequestBuilder must be configured in OpenSAML");
		this.issuerBuilder = (IssuerBuilder) registry.getBuilderFactory().getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		Assert.notNull(this.issuerBuilder, "issuerBuilder must be configured in OpenSAML");
		this.nameIdBuilder = (NameIDBuilder) registry.getBuilderFactory().getBuilder(NameID.DEFAULT_ELEMENT_NAME);
		Assert.notNull(this.nameIdBuilder, "nameIdBuilder must be configured in OpenSAML");
		this.nameIdPolicyBuilder = (NameIDPolicyBuilder) registry.getBuilderFactory()
			.getBuilder(NameIDPolicy.DEFAULT_ELEMENT_NAME);
		Assert.notNull(this.nameIdPolicyBuilder, "nameIdPolicyBuilder must be configured in OpenSAML");
	}

	void setRelayStateResolver(Converter<HttpServletRequest, String> relayStateResolver) {
		this.relayStateResolver = relayStateResolver;
	}

	void setRequestMatcher(RequestMatcher requestMatcher) {
		this.requestMatcher = requestMatcher;
	}

	<T extends AbstractSaml2AuthenticationRequest> T resolve(HttpServletRequest request) {
		return resolve(request, (registration, logoutRequest) -> {
		});
	}

	<T extends AbstractSaml2AuthenticationRequest> T resolve(HttpServletRequest request,
			BiConsumer<RelyingPartyRegistration, AuthnRequest> authnRequestConsumer) {
		RequestMatcher.MatchResult result = this.requestMatcher.matcher(request);
		if (!result.isMatch()) {
			return null;
		}
		String registrationId = result.getVariables().get("registrationId");
		RelyingPartyRegistration registration = this.relyingPartyRegistrationResolver.resolve(request, registrationId);
		if (registration == null) {
			return null;
		}
		UriResolver uriResolver = RelyingPartyRegistrationPlaceholderResolvers.uriResolver(request, registration);
		String entityId = uriResolver.resolve(registration.getEntityId());
		String assertionConsumerServiceLocation = uriResolver
			.resolve(registration.getAssertionConsumerServiceLocation());
		AuthnRequest authnRequest = this.authnRequestBuilder.buildObject();
		authnRequest.setForceAuthn(Boolean.FALSE);
		authnRequest.setIsPassive(Boolean.FALSE);
		authnRequest.setProtocolBinding(registration.getAssertionConsumerServiceBinding().getUrn());
		Issuer iss = this.issuerBuilder.buildObject();
		iss.setValue(entityId);
		authnRequest.setIssuer(iss);
		authnRequest.setDestination(registration.getAssertingPartyMetadata().getSingleSignOnServiceLocation());
		authnRequest.setAssertionConsumerServiceURL(assertionConsumerServiceLocation);
		if (registration.getNameIdFormat() != null) {
			NameIDPolicy nameIdPolicy = this.nameIdPolicyBuilder.buildObject();
			nameIdPolicy.setFormat(registration.getNameIdFormat());
			authnRequest.setNameIDPolicy(nameIdPolicy);
		}
		authnRequestConsumer.accept(registration, authnRequest);
		if (authnRequest.getID() == null) {
			authnRequest.setID(TraceSupport.getOwnTraceParentForSaml());
		}
		String relayState = this.relayStateResolver.convert(request);
		Saml2MessageBinding binding = registration.getAssertingPartyMetadata().getSingleSignOnServiceBinding();
		if (binding == Saml2MessageBinding.POST) {
			if (registration.getAssertingPartyMetadata().getWantAuthnRequestsSigned()
					|| registration.isAuthnRequestsSigned()) {
				OpenSaml5SigningUtils.sign(authnRequest, registration);
			}
			String xml = serialize(authnRequest);
			String encoded = Saml2Utils.samlEncode(xml.getBytes(StandardCharsets.UTF_8));
			return (T) Saml2PostAuthenticationRequest.withRelyingPartyRegistration(registration)
				.samlRequest(encoded)
				.relayState(relayState)
				.id(authnRequest.getID())
				.build();
		}
		else {
			String xml = serialize(authnRequest);
			String deflatedAndEncoded = Saml2Utils.samlEncode(Saml2Utils.samlDeflate(xml));
			Saml2RedirectAuthenticationRequest.Builder builder = Saml2RedirectAuthenticationRequest
				.withRelyingPartyRegistration(registration)
				.samlRequest(deflatedAndEncoded)
				.relayState(relayState)
				.id(authnRequest.getID());
			if (registration.getAssertingPartyMetadata().getWantAuthnRequestsSigned()
					|| registration.isAuthnRequestsSigned()) {
				OpenSaml5SigningUtils.QueryParametersPartial parametersPartial = OpenSaml5SigningUtils.sign(registration)
					.param(Saml2ParameterNames.SAML_REQUEST, deflatedAndEncoded);
				if (relayState != null) {
					parametersPartial = parametersPartial.param(Saml2ParameterNames.RELAY_STATE, relayState);
				}
				Map<String, String> parameters = parametersPartial.parameters();
				builder.sigAlg(parameters.get(Saml2ParameterNames.SIG_ALG))
					.signature(parameters.get(Saml2ParameterNames.SIGNATURE));
			}
			return (T) builder.build();
		}
	}

	private String serialize(AuthnRequest authnRequest) {
		try {
			Element element = this.marshaller.marshall(authnRequest);
			return SerializeSupport.nodeToString(element);
		}
		catch (MarshallingException ex) {
			throw new Saml2Exception(ex);
		}
	}

}
