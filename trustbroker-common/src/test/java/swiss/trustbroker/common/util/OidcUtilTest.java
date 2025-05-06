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

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class OidcUtilTest {

	@ParameterizedTest
	@CsvSource({
			",,,",
			",iss1,,", // iss alone not allowed
			",,sess1,", // sid alone not allowed
			",iss1,sess1,?iss=iss1&sid=sess1",
			"https//localhost,iss1,sess1,https//localhost?iss=iss1&sid=sess1",
			",https://issuer,https://session,?iss=https%3A%2F%2Fissuer&sid=https%3A%2F%2Fsession",
	})
	void appendFrontchannelLogoutQueryString(String url, String iss, String sid, String result) {
		assertThat(OidcUtil.appendFrontchannelLogoutQueryString(url, iss, sid), is(result));
	}

	@ParameterizedTest
	@CsvSource({
			"https://host1/path,false",
			"https://host1/path/subpath,true",
			"https://host1/path/subpath/,false",
			"https://host2/path/any,true",
			"https://host2/path/any/subpath,true",
			"https://host3,true",
			"https://host3/,true",
			"https://host3/any,true",
			"https://host3:443/any,true",
			"https://host3/any/subpath,true",
			"https://host4/any,true",
			"https://host4:443/any,true"
	})
	void testRedirectUriMatch(String url, boolean expectedResult) {
		var config = Set.of(
				"https://host1/path/subpath",
				"https://host2/path/.*",
				"https://host3/.*",
				"https://host4:443/.*"
		);
		assertThat(UrlAcceptor.isRedirectUrlOkForAccess(url, config), is(expectedResult));
	}

	@Test
	void testClientIdFromAuthorizationValid() {
		var authHeader = "bearer " +
				"eyJraWQiOiIyM2Q2ZTNhZC1iZDc3LTRmZDAtYWE2ZC0wMWE3NGI1NjFmMjciLCJhbGciOiJSUzI1NiJ9." +
				"eyJzdWIiOiIxMjM0NSIsImF1ZCI6IlRFU1RSUCIsImFjciI6WyJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6Y2xhc3NlczpOb21hZFRlbGVwaG9ueSJdLCJuYmYiOjE2ODkwOTEyNTEsInNjb3BlIjpbIm9wZW5pZCIsImVtYWlsIl0sImF1dGhfdGltZSI6MTY4OTA5MTI1MSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwiZXhwIjoxNjg5MDkyNDUxLCJpYXQiOjE2ODkwOTEyNTEsImp0aSI6IjYyNmZiNzgzLWQ3MDYtNGI0Yy05NDk0LThkMjI4OTI2NWIyYiJ9Cg." +
				"makYE597FiXOAjRPBifze-6PHJxR6XQmVBmqTf5IifNGyMAuUJnei0nJbmFPuAYQeBgkXbZk8zqcl8jggiAVvdgS-tkY_VRBeibCcAyO_JePfgLWK0GsTBpoK4PuQoWn9OY2w43WYIpG--XsiVRnPuBXJVTkR4zc2X_Z7xpAUoFdUJd-4eLc1Mr1L4JPRDSOFGzHE_Hd4e3DxXQ6ilkKFxzFLgoHz8ohWt4m8x9iur7EQ-AY3H-yaQkT8zoAR67hcYrkuiCV2KArKyIPmMdThi-evbbTd-opcDDlc2GhjsR9XKsv-nI8S7tmjx99ljTiN93nvuVnil_iUoNqdSG8MA";
		var clId = OidcUtil.getClientIdFromAuthorizationHeader(authHeader);
		assertThat(clId, equalTo("TESTRP"));
	}

	@Test
	void testClientIdFromBasicAuth() {
		var authHeader = "Basic Y2xpZW50SUQ6c2VjcmV0Cg==";
		var clId = OidcUtil.getClientIdFromAuthorizationHeader(authHeader);
		assertThat(clId, equalTo("clientID"));
	}

	@Test
	void testClientIdFromAuthorizationInvalid() {
		// ERROR log only
		var clId = OidcUtil.getClientIdFromAuthorizationHeader("invalid");
		assertThat(clId, nullValue());
	}

	@Test
	void testGetBasicAuthorizationHeader() {
		assertThat(OidcUtil.getBasicAuthorizationHeader("test", "secret"), is("Basic dGVzdDpzZWNyZXQ="));
	}

}
