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
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static swiss.trustbroker.config.TestConstants.LATEST_INVALID_DEFINITION_PATH;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.test.context.ContextConfiguration;
import swiss.trustbroker.common.setup.service.GitService;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.service.XmlConfigStatusService;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.ClaimsProvider;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderDefinitions;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderSetup;
import swiss.trustbroker.federation.xmlconfig.FeatureEnum;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.RelyingPartySetup;
import swiss.trustbroker.federation.xmlconfig.Sso;
import swiss.trustbroker.federation.xmlconfig.SsoGroup;
import swiss.trustbroker.federation.xmlconfig.SsoGroupSetup;
import swiss.trustbroker.homerealmdiscovery.util.ClaimsProviderUtil;
import swiss.trustbroker.homerealmdiscovery.util.RelyingPartySetupUtil;
import swiss.trustbroker.metrics.service.MetricsService;
import swiss.trustbroker.oidc.ClientConfigInMemoryRepository;
import swiss.trustbroker.script.service.ScriptService;
import swiss.trustbroker.test.saml.util.SamlTestBase;

@SpringBootTest
@ContextConfiguration(classes = { AppConfigService.class })
class AppConfigServiceTest {

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

	@MockBean
	private MetricsService metricsService;

	@MockBean
	private XmlConfigStatusService xmlConfigStatusService;

	@Autowired
	private AppConfigService appConfigService;

	@Test
	void TestCheckRpSsoIntegrity() {
		var ssoGroup = SsoGroup.builder().name("sso1").build();
		var rpOk = RelyingParty.builder()
							   .id("rp3")
							   .sso(Sso.builder().enabled(true).groupName(ssoGroup.getName()).build())
							   .build();
		var rpUnknownSsoGroup = RelyingParty.builder()
											.id("rp1")
											.sso(Sso.builder().enabled(true).groupName("unknown").build())
											.build();
		var rpMissingSsoGroup = RelyingParty.builder()
											.id("rp2")
											.sso(Sso.builder().enabled(true).build())
											.build();
		var rpSetup = RelyingPartySetup.builder().relyingParties(List.of(rpOk, rpMissingSsoGroup, rpUnknownSsoGroup)).build();
		var ssoSetup = SsoGroupSetup.builder().ssoGroups(List.of(ssoGroup)).build();

		AppConfigService.checkRpSsoIntegrity(rpSetup, ssoSetup);

		assertThat(rpOk.isValid(), is(true));
		assertThat(rpOk.getValidationStatus().getErrors(), hasSize(0));
		assertThat(rpUnknownSsoGroup.isValid(), is(true));
		assertThat(rpUnknownSsoGroup.getValidationStatus().getErrors(), hasSize(1));
		assertThat(rpMissingSsoGroup.isValid(), is(true));
		assertThat(rpMissingSsoGroup.getValidationStatus().getErrors(), hasSize(1));
	}

	@Test
	void testCheckCpConfigIntegrity() {
		var existingClaimsProvider = "claimsProvider1";
		var claimsProvider1 = ClaimsProvider.builder()
											.id(existingClaimsProvider)
											.build();
		var missingClaimsProvider = "claimsProvider2";
		var claimsProvider2 = ClaimsProvider.builder()
											.id(missingClaimsProvider)
											.build();
		var cpDefinition = ClaimsProviderDefinitions.builder()
													.claimsProviders(List.of(claimsProvider1, claimsProvider2))
													.build();
		var claimsParties = new ArrayList<ClaimsParty>(); // must be mutable
		var claimsParty1 = ClaimsParty.builder()
									  .id(existingClaimsProvider)
									  .build();
		claimsParties.add(claimsParty1);
		var cpSetup = ClaimsProviderSetup.builder()
										 .claimsParties(claimsParties)
										 .build();

		AppConfigService.checkCpConfigIntegrity(cpDefinition, cpSetup);

		assertThat(claimsParty1.isValid(), is(true));
		assertThat(claimsParty1.getValidationStatus().hasErrors(), is(false));

		assertThat(cpSetup.getClaimsParties(), hasSize(2));
		assertThat(cpSetup.getClaimsParties().get(0), is(claimsParty1));

		var invalidCp = cpSetup.getClaimsParties().get(1);
		assertThat(invalidCp.getId(), is(missingClaimsProvider));
		assertThat(invalidCp.isValid(), is(false));
		assertThat(invalidCp.getValidationStatus().hasErrors(), is(true));
	}

	@Test
	void testInvalidBase() {
		var relyingPartySetup = loadRelyingParty("SetupRPInvalidBase.xml");
		assertDoesNotThrow(() ->
				RelyingPartySetupUtil.loadRelyingParty(
						relyingPartySetup.getRelyingParties(), LATEST_INVALID_DEFINITION_PATH, LATEST_INVALID_DEFINITION_PATH,
						properties, Collections.emptyList()));
		var rp = relyingPartySetup.getRelyingParties().get(0);
		assertEquals(FeatureEnum.INVALID, rp.getEnabled());
	}

	@Test
	void loadConfigFromFileInvalidFile() {
		var relyingPartySetup = loadRelyingParty("SetupRPInvalidCert.xml");
		assertDoesNotThrow(() ->
				RelyingPartySetupUtil.loadRelyingParty(
						relyingPartySetup.getRelyingParties(), LATEST_INVALID_DEFINITION_PATH, LATEST_INVALID_DEFINITION_PATH,
						properties, Collections.emptyList()));
		var rp = relyingPartySetup.getRelyingParties().get(0);
		// after RelyingPartySetupUtils validation, it is still valid
		assertEquals(FeatureEnum.TRUE, rp.getEnabled());
		appConfigService.checkAndLoadRelyingPartyCertificates(relyingPartySetup);
		assertEquals(FeatureEnum.INVALID, rp.getEnabled());
	}

	private RelyingPartySetup loadRelyingParty(String fileName) {
		var file = SamlTestBase.fileFromClassPath(LATEST_INVALID_DEFINITION_PATH + fileName);
		var relyingPartySetup = ClaimsProviderUtil.loadRelyingPartySetup(file);
		assertThat(relyingPartySetup.getRelyingParties(), hasSize(1));
		var rp = relyingPartySetup.getRelyingParties().get(0);
		// after loading, it is still valid
		assertEquals(FeatureEnum.TRUE, rp.getEnabled());
		return relyingPartySetup;
	}
}
