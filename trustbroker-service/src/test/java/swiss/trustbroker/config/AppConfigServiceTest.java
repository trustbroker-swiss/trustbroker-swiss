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
package swiss.trustbroker.config;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Collections;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.test.context.ContextConfiguration;
import swiss.trustbroker.common.setup.service.GitService;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.xmlconfig.FeatureEnum;
import swiss.trustbroker.federation.xmlconfig.RelyingPartySetup;
import swiss.trustbroker.homerealmdiscovery.util.ClaimsProviderUtil;
import swiss.trustbroker.homerealmdiscovery.util.RelyingPartySetupUtil;
import swiss.trustbroker.oidc.ClientConfigInMemoryRepository;
import swiss.trustbroker.script.service.ScriptService;
import swiss.trustbroker.test.saml.util.SamlTestBase;

@SpringBootTest
@ContextConfiguration(classes = { AppConfigService.class })
class AppConfigServiceTest {

	public static final String PATH = "latest/invaliddefs/";

	@MockBean
	private ApplicationEventPublisher eventPublisher;

	@MockBean
	private TrustBrokerProperties properties;

	@MockBean
	private GitService gitService;

	@MockBean
	private RelyingPartyDefinitions relyingPartyDefinitions;

	@MockBean
	private ScriptService scriptService;

	@MockBean
	private ClientConfigInMemoryRepository clientConfigInMemoryRepository;

	@Autowired
	private AppConfigService appConfigService;

	@Test
	void testInvalidBase() {
		var relyingPartySetup = loadRelyingParty("SetupRPInvalidBase.xml");
		assertDoesNotThrow(() ->
				RelyingPartySetupUtil.loadRelyingParty(
						relyingPartySetup.getRelyingParties(), PATH, PATH, properties, Collections.emptyList()));
		var rp = relyingPartySetup.getRelyingParties().get(0);
		assertEquals(FeatureEnum.INVALID, rp.getEnabled());
	}

	@Test
	void loadConfigFromFileInvalidFile() {
		var relyingPartySetup = loadRelyingParty("SetupRPInvalidCert.xml");
		assertDoesNotThrow(() ->
				RelyingPartySetupUtil.loadRelyingParty(
						relyingPartySetup.getRelyingParties(), PATH, PATH, properties, Collections.emptyList()));
		var rp = relyingPartySetup.getRelyingParties().get(0);
		// after RelyingPartySetupUtils validation, it is still valid
		assertEquals(FeatureEnum.TRUE, rp.getEnabled());
		appConfigService.checkAndLoadRelyingPartyCertificates(relyingPartySetup);
		assertEquals(FeatureEnum.INVALID, rp.getEnabled());
	}

	private RelyingPartySetup loadRelyingParty(String fileName) {
		var file = SamlTestBase.fileFromClassPath(PATH + fileName);
		var relyingPartySetup = ClaimsProviderUtil.loadRelyingPartySetup(file);
		assertThat(relyingPartySetup.getRelyingParties(), hasSize(1));
		var rp = relyingPartySetup.getRelyingParties().get(0);
		// after loading, it is still valid
		assertEquals(FeatureEnum.TRUE, rp.getEnabled());
		return relyingPartySetup;
	}
}
