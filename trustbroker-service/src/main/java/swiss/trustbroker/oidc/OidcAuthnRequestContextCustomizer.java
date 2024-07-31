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

package swiss.trustbroker.oidc;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

import com.google.common.collect.Sets;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.oidc.opensaml5.OpenSaml5AuthenticationRequestResolver;
import swiss.trustbroker.oidc.session.OidcSessionSupport;

@AllArgsConstructor
@Slf4j
class OidcAuthnRequestContextCustomizer implements Consumer<OpenSaml5AuthenticationRequestResolver.AuthnRequestContext> {

	private final TrustBrokerProperties properties;

	private final RelyingPartyDefinitions relyingPartyDefinitions;

	@Override
	public void accept(OpenSaml5AuthenticationRequestResolver.AuthnRequestContext authnRequestContext) {
		var authnRequest = authnRequestContext.getAuthnRequest();
		// Pass on client_id as applicationName too via SAML ProviderName
		authnRequest.setProviderName(OidcSessionSupport.getOidcClientId(authnRequestContext.getRequest()));
		// Handle prompt=login as forceAuthn=true
		if (OidcUtil.isOidcPromptLogin(authnRequestContext.getRequest())) {
			authnRequest.setForceAuthn(true);
		}
		// map HTTP acr_values or config Qoa settings to context classes
		var contextClasses = constructAuthnRequestContextClasses(authnRequestContext.getRequest());
		authnRequest.setRequestedAuthnContext(contextClasses);
	}

	private RequestedAuthnContext constructAuthnRequestContextClasses(HttpServletRequest httpServletRequest) {
		// QoA/LoA mapping
		var requestedAuthnContext = OpenSamlUtil.buildSamlObject(RequestedAuthnContext.class);
		var acrValues = httpServletRequest.getParameter(OidcUtil.OIDC_ACR_VALUES);
		var clientId = OidcConfigurationUtil.getClientIdFromRequest(httpServletRequest);
		Set<String> qoas = new HashSet<>();
		if (acrValues != null) {
			qoas.addAll(Arrays.stream(acrValues.split(","))
					.toList());
			log.debug("Got qoas={} from HTTP request {}={}", qoas, OidcUtil.OIDC_ACR_VALUES, StringUtil.clean(acrValues));
		}
		if (qoas.isEmpty()) {
			qoas = getQoaFromConfiguration(clientId);
			log.debug("Got qoas={} from clientId={} configuration", qoas, clientId);
		}
		var authnContextClassRefs = mapQoaScopeToAuthnContextClassRef(qoas);
		if (!authnContextClassRefs.isEmpty()) {
			requestedAuthnContext.getAuthnContextClassRefs()
								 .addAll(authnContextClassRefs);
		}
		return requestedAuthnContext;
	}

	private Set<String> getQoaFromConfiguration(String clientId) {
		List<String> qoas = null;
		// from Oidc Client (if multiple clients differ in Qoa requirements)
		var oidcClient = relyingPartyDefinitions.getOidcClientConfigById(clientId, properties);
		if (oidcClient.isPresent() && oidcClient.get()
												.getQoa() != null) {
			qoas = oidcClient.get()
							 .getQoa()
							 .getClasses();
		}
		// from RelyingParty
		if (qoas == null) {
			var relyingParty = relyingPartyDefinitions.getRelyingPartyByOidcClientId(clientId, clientId, properties, false);
			if (relyingParty.getQoa() != null) {
				qoas = relyingParty.getQoa()
								   .getClasses();
			}
		}
		// global fallback
		if (qoas == null) {
			qoas = getDefaultQoa();
			if (log.isWarnEnabled()) {
				log.info("Missing acr_values in request, RelyingParty.Qoa and Oidc.Client.Qoa configuration for clientId={}."
						+ " Using global oidcDefaultQoa={}", StringUtil.clean(clientId), qoas);
			}
		}
		return Sets.newHashSet(qoas);
	}

	private List<String> getDefaultQoa() {
		var oidc = properties.getOidc();
		if (oidc.getDefaultQoa() != null) {
			return List.of(oidc.getDefaultQoa());
		}
		log.error("Missing Qoa default value from application.yml.");
		return new ArrayList<>();
	}

	private static List<AuthnContextClassRef> mapQoaScopeToAuthnContextClassRef(Set<String> qoas) {
		var ret = new ArrayList<AuthnContextClassRef>();
		for (var qoa : qoas) {
			ret.add(createContextClassRef(qoa));
		}
		return ret;
	}

	private static AuthnContextClassRef createContextClassRef(String classRef) {
		var authnContextClassRef = OpenSamlUtil.buildSamlObject(AuthnContextClassRef.class);
		authnContextClassRef.setURI(classRef);
		return authnContextClassRef;
	}
}
