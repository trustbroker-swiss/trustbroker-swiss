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
package swiss.trustbroker.common.util;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.test.saml.util.SamlTestBase;

class FileServerUtilTest {

	private static final String ASSETS = "assets";

	public static final String TRANSLATIONS = "translations";

	@Test
	void returnFileContentValid() throws Exception {
		var response = new MockHttpServletResponse();
		var directory = SamlTestBase.fileFromClassPath(ASSETS).getAbsolutePath();
		FileServerUtil.returnFileContent(response, directory, "test/test.txt", MediaType.TEXT_PLAIN_VALUE);
		assertThat(response.getHeader(HttpHeaders.CONTENT_TYPE), is(MediaType.TEXT_PLAIN_VALUE));
		assertThat(response.getContentAsString(), is("""
				Test
				"""));
	}

	@Test
	void returnFileContentDetection() throws Exception {
		var response = new MockHttpServletResponse();
		var directory = SamlTestBase.fileFromClassPath(ASSETS).getAbsolutePath();
		FileServerUtil.returnFileContent(response, directory, "test/test.svg", null);
		assertThat(response.getHeader(HttpHeaders.CONTENT_TYPE), is("image/svg+xml"));
		assertThat(response.getContentAsString(), is("""
				<svg>
				</svg>
				"""));
	}

	@Test
	void returnFileContentBlocked() {
		var response = new MockHttpServletResponse();
		var directory = SamlTestBase.fileFromClassPath(ASSETS).getAbsolutePath();
		// invalid path traversal
		assertThrows(RequestDeniedException.class,
				() -> FileServerUtil.returnFileContent(response, directory, "../private.txt", MediaType.TEXT_PLAIN_VALUE));
	}

	@Test
	void readTranslationFile() {
		var directory = SamlTestBase.fileFromClassPath(TRANSLATIONS).getAbsolutePath();
		var result = FileServerUtil.readTranslationFile(directory, "en", "de", "42.0");
		assertThat(result, is("""
				{
					"language": "Deutsch",
					"version": "XTB/42.0"
				}
				"""));
	}

	@Test
	void readTranslationFileDefaultLanguage() {
		var directory = SamlTestBase.fileFromClassPath(TRANSLATIONS).getAbsolutePath();
		var result = FileServerUtil.readTranslationFile(directory, "en", "fr", "TrustBroker/B1.2");
		assertThat(result, is("""
				{
					"language": "English",
					"version": "XTB/TrustBroker/B1.2"
				}
				"""));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"../assets/it",
			"../assets/en"
	})
	void readTranslationFileBlocked(String language) {
		var directory = SamlTestBase.fileFromClassPath(TRANSLATIONS).getAbsolutePath();
		// file exists, but invalid path traversal -> default language is used
		var result = FileServerUtil.readTranslationFile(directory, "en", language, null);
		assertThat(result, is("""
				{
					"language": "English",
					"version": "XTB/VERSION@STAGE"
				}
				"""));
	}

}
