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

package swiss.trustbroker.homerealmdiscovery.util;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.federation.xmlconfig.FeatureEnum;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.RelyingPartySetup;
import swiss.trustbroker.test.saml.util.SamlTestBase;

class XmlConfigUtilTest {

	@Test
	void createUnmarshallerValidClass() {
		var result = XmlConfigUtil.createUnmarshaller(RelyingParty.class);
		assertThat(result, is(not(nullValue())));
	}

	@Test
	void createUnmarshallerUnsupportedClass() {
		assertThrows(TechnicalException.class, () -> XmlConfigUtil.createUnmarshaller(String.class));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"ClaimsProviderDefinitions.xml,ClaimsProviderDefinitions",
			"SetupCP.xml,ClaimsProviderSetup",
			"ProfileRP_Standard.xml,RelyingParty",
			"SetupRP.xml,RelyingPartySetup",
			"SetupSSOGroups.xml,SsoGroupSetup" })
	void loadConfigFromFileValidFile(String file, String className) throws ClassNotFoundException {
		var path = "latest/definitions/";
		var cls = getDtoClass(className);
		var def = SamlTestBase.fileFromClassPath(path + file);
		var result = XmlConfigUtil.loadConfigFromFile(def, cls);
		assertThat(result, is(not(nullValue())));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"SetupRPInvalidElement.xml,RelyingParty",
			"SetupRPInvalidAttribute.xml,RelyingParty",
			"SetupRPMissingElement.xml,RelyingParty",
			"SetupRPInvalidXml.xml,RelyingParty",
			"SetupCPInvalidXml.xml,ClaimsProviderSetup",
	})
	void loadConfigFromFileInvalidFile(String file, String className) throws ClassNotFoundException {
		var path = "latest/invaliddefs/";
		var cls = getDtoClass(className);
		var def = SamlTestBase.fileFromClassPath(path + file);
		var ex = assertThrows(TechnicalException.class,
				() -> XmlConfigUtil.loadConfigFromFile(def, cls));
		assertThat(ex.getInternalMessage(), startsWith("Invalid configFile"));
	}

	@Test
	void loadInvalidEnum() {
		var def = SamlTestBase.fileFromClassPath("latest/invaliddefs/SetupRPInvalidEnabled.xml");
		var result = XmlConfigUtil.loadConfigFromFile(def, RelyingPartySetup.class);
		assertThat(result.getRelyingParties().get(0).getEnabled(), is(FeatureEnum.INVALID));
	}

	@Test
	void loadConfigFromFileInvalidFileCheckMessage() throws ClassNotFoundException {
		var file = "latest/invaliddefs/SetupRPInvalidElement.xml";
		var def = SamlTestBase.fileFromClassPath(file);
		try {
			XmlConfigUtil.loadConfigFromFile(def, RelyingPartySetup.class);
			fail("Expected exception");
		}
		catch (TechnicalException ex) {
			assertThat(ex.getInternalMessage(), containsString("SAXParseException; lineNumber:"));
		}
	}

	private static Class<?> getDtoClass(String className) throws ClassNotFoundException {
		return Class.forName(RelyingParty.class.getPackageName() + '.' + className);
	}
}
