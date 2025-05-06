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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;

import net.shibboleth.shared.codec.HTMLEncoder;
import org.apache.velocity.app.VelocityEngine;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.common.binding.artifact.SAMLArtifactMap;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.api.saml.dto.DestinationType;
import swiss.trustbroker.api.saml.dto.EncodingParameters;
import swiss.trustbroker.common.saml.service.ArtifactCacheService;
import swiss.trustbroker.common.saml.util.SamlIoUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.ArtifactResolution;
import swiss.trustbroker.config.dto.SamlProperties;
import swiss.trustbroker.saml.test.util.ServiceSamlTestUtil;
import swiss.trustbroker.test.saml.util.SamlHttpTestBase;
import swiss.trustbroker.test.saml.util.SamlTestBase;

@SpringBootTest(classes = { SamlServiceTestConfiguration.class, SamlOutputService.class })
class SamlOutputServiceTest extends ServiceSamlTestUtil {

	private static final String RELAY_STATE = "state123";

	private static final String ISSUER_ID = "selfId";

	private static final String ENDPOINT = "https://localhost/service";

	private static final DestinationType DESTINATION_ALIAS = DestinationType.RP;

	@MockitoBean
	private TrustBrokerProperties trustBrokerProperties;

	@MockitoBean
	private ArtifactCacheService artifactCacheService;

	@Autowired
	private VelocityEngine velocityEngine;

	@Autowired
	private SamlOutputService samlOutputService;

	@MockitoBean
	private SAMLArtifactMap artifactMap;

	@BeforeAll
	static void init() {
		SamlTestBase.setup();
	}

	@BeforeEach
	void setUp() {
		var saml = new SamlProperties();
		var ar = new ArtifactResolution();
		saml.setArtifactResolution(ar);
		doReturn(saml).when(trustBrokerProperties).getSaml();
		doReturn(ISSUER_ID).when(trustBrokerProperties).getIssuer();
	}

	@Test
	void sendPostRequest() throws Exception {
		var request = loadAuthnRequest();
		var credential = SamlTestBase.dummyCredential();
		var httpResponse = new MockHttpServletResponse();
		var encodingParams = EncodingParameters.builder().build();

		samlOutputService.sendRequest(request, credential, RELAY_STATE, ENDPOINT, httpResponse, encodingParams, DESTINATION_ALIAS);

		var encodedRequest = extractSamlPostRequest(httpResponse.getContentAsString());
		assertThat(encodedRequest.getID(), is(request.getID()));
		validateResponse(httpResponse.getContentAsString());
	}

	@Test
	void sendArtifactRequest() throws Exception {
		var request = loadAuthnRequest();
		var credential = SamlTestBase.dummyCredential();
		var httpResponse = new MockHttpServletResponse();
		var encodingParams = EncodingParameters.builder().useArtifactBinding(true).build();
		doReturn(artifactMap).when(artifactCacheService).getArtifactMap();

		samlOutputService.sendRequest(request, credential, RELAY_STATE, ENDPOINT, httpResponse, encodingParams, DESTINATION_ALIAS);

		var encodedArtifact = extractSamlArtifactValue(httpResponse.getContentAsString());
		var requestIssuer = request.getIssuer().getValue();
		verify(artifactMap).put(encodedArtifact, requestIssuer, requestIssuer, request);
		validateResponse(httpResponse.getContentAsString());
	}

	@Test
	void sendPostResponse() throws Exception {
		var response = loadAuthnResponse();
		var httpResponse = new MockHttpServletResponse();
		var encodingParams = EncodingParameters.builder().build();

		samlOutputService.sendResponse(response, null, RELAY_STATE, ENDPOINT, httpResponse, encodingParams, DESTINATION_ALIAS);

		var encodedResponse = extractSamlPostResponse(httpResponse.getContentAsString());
		assertThat(encodedResponse.getID(), is(response.getID()));
		validateResponse(httpResponse.getContentAsString());
	}

	@Test
	void sendArtifactResponse() throws Exception {
		var response = loadAuthnResponse();
		sendResponseViaArtifactBinding(response);
	}

	@Test
	void sendLogoutResponse() throws Exception {
		var response = loadLogoutResponse();
		sendResponseViaArtifactBinding(response);
	}

	private void sendResponseViaArtifactBinding(StatusResponseType response) throws Exception {
		var httpResponse = new MockHttpServletResponse();
		var encodingParams = EncodingParameters.builder().useArtifactBinding(true).build();
		doReturn(artifactMap).when(artifactCacheService).getArtifactMap();

		samlOutputService.sendResponse(response, null, RELAY_STATE, ENDPOINT, httpResponse, encodingParams, DESTINATION_ALIAS);

		var encodedArtifact = extractSamlArtifactValue(httpResponse.getContentAsString());
		var requestIssuer = response.getIssuer().getValue();
		verify(artifactMap).put(encodedArtifact, requestIssuer, requestIssuer, response);
		validateResponse(httpResponse.getContentAsString());
	}

	private static void validateResponse(String content) {
		assertThat(content, containsString(" action=\"" + HTMLEncoder.encodeForHTMLAttribute(ENDPOINT) + '"'));
		var encodedRelayState = SamlHttpTestBase.extractHtmlFormValue( content, SamlIoUtil.SAML_RELAY_STATE);
		assertThat(encodedRelayState, is(RELAY_STATE));
	}

}
