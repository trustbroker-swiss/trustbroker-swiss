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

package swiss.trustbroker.script.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ContextConfiguration;
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.saml.dto.CpResponse;

@SpringBootTest
@ContextConfiguration(classes = ScriptService.class)
class ScriptServiceTest {

	private static final String SCRIPTS_PATH = "scripts/"; // on classpath

	@Autowired
	ScriptService scriptService;

	@MockBean
	RelyingPartySetupService relyingPartySetupService;

	@MockBean
	TrustBrokerProperties trustBrokerProperties;

	@BeforeEach
	public void setup() {
		SamlInitializer.initSamlSubSystem();
	}

	@Test
	void testRemoveIdmUserDetailsAfterIdm() {
		String scriptName = SCRIPTS_PATH + "RemoveIdmUserDetailsAfterIdm.groovy";
		// beans
		CpResponse cpResponse = givenResponseWithIdmUserDetails();
		int originSize1 = cpResponse.getAttributes().size();
		int userSize1 = cpResponse.getUserDetails().size();
		// process
		scriptService.init(scriptName);
		scriptService.processOnResponse(scriptName, cpResponse, null, null);
		// process (removes one query)
		int originSize2 = cpResponse.getAttributes().size();
		int userSize2 = cpResponse.getUserDetails().size();
		assertEquals(userSize1 + 1, userSize2,
				"Groovy script " + scriptName + " did not manipulate USERDETAILS as expected");
		assertEquals(originSize1 + 1, originSize2,
				"Groovy script " + scriptName + " did not manipulate ORIGINATTRS as expected");
	}

	@Test
	void testShortSamlAttributeNames() {
		String scriptName = SCRIPTS_PATH + "AdjustOidcAttributeNames.groovy";

		// data
		var cpResponse = CpResponse.builder()
									.attributes(Map.of(
						Definition.builder().namespaceUri("http://fq.stuff.1/name1").build(), List.of("value1"),
						Definition.builder().namespaceUri("http://fq.stuff.11/name1").build(), List.of("value1")
				))
									.userDetails(Map.of(
						Definition.builder().namespaceUri("http://fq.stuff.2/name2").build(), List.of("value2"),
						Definition.builder().namespaceUri("http://fq.stuff.22/name2").build(), List.of("value2")
				))
									.properties(Map.of(
						Definition.builder().namespaceUri("http://fq.stuff.3/name3").build(), List.of("value3"),
						Definition.builder().namespaceUri("http://fq.stuff.33/name3").build(), List.of("value3")
				))
									.rpContext(Map.of(
						HttpHeaders.REFERER, "https://identity-test.trustbroker.swiss"
				))
									.build();
		// process
		scriptService.init(scriptName);
		scriptService.processOnResponse(scriptName, cpResponse, null, null);

		// check (arbitrary which entry of the above wins)
		assertEquals("value1", cpResponse.getAttribute("name1"));
		assertEquals("value2", cpResponse.getUserDetail("name2"));
		assertEquals("value3", cpResponse.getProperty("name3"));
	}

	private static CpResponse givenResponseWithIdmUserDetails() {
		CpResponse cpResponse = new CpResponse();
		// CP data
		Map<Definition, List<String>> cpAttrs = new HashMap<>();
		cpAttrs.put(Definition.builder().name("ORIGIN1").build(), List.of("ORIGIN-VALUE1"));
		cpResponse.setAttributes(cpAttrs);
		// IDM data
		Map<Definition, List<String>> userDetails = new HashMap<>();
		userDetails.put(Definition.builder().name("SHORT1").namespaceUri("LONG1").build(), List.of("VALUE1"));
		cpResponse.setUserDetails(userDetails);
		return cpResponse;
	}

}
