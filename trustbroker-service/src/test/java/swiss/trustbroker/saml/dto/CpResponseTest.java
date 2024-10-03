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

package swiss.trustbroker.saml.dto;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import java.util.List;

import org.junit.jupiter.api.Test;

class CpResponseTest {

	@Test
	void testCpAttributes() {
		// set/get
		var cpResponse = new CpResponse();
		cpResponse.setAttribute(null, null);
		cpResponse.setAttribute(null, "NULL");
		cpResponse.setAttribute("NULL", null);
		cpResponse.setAttributes("NULL", List.of());
		assertThat(cpResponse.getAttributes()
							 .size(), is(0));
		cpResponse.setAttribute("attr1", "value1");
		cpResponse.setAttributes("attr1", List.of("value2", "value3"));
		assertThat(cpResponse.getAttributes()
							 .size(), is(1));
		assertThat(cpResponse.getAttributes("attr1"), contains("value2", "value3"));
		assertThat(cpResponse.getAttribute("attr1"), is("value2"));
		assertThat(cpResponse.getAttribute("attr2"), is(nullValue()));


		// add
		cpResponse.addAttribute("attr1", "value4");
		assertThat(cpResponse.getAttributes("attr1"), contains("value2", "value3", "value4"));
		cpResponse.addAttribute("attr2", "value2");
		assertThat(cpResponse.getAttributes("attr2"), contains("value2"));

		// remove
		cpResponse.removeAttributes("attr1");
		assertThat(cpResponse.getAttribute("attr1"), is(nullValue()));
		//assertThat(cpResponse.getAttribute("attr2"), is("value2"));
	}

	@Test
	void testIdmAttributes() {
		// set/get
		var cpResponse = new CpResponse();
		cpResponse.setUserDetail(null, null, null);
		cpResponse.setUserDetail(null, null, "NULL");
		cpResponse.setUserDetail(null, "NULL", null);
		cpResponse.setUserDetail(null, "NULL", "NULL"); // added
		cpResponse.setUserDetail("NULL", null, null);
		cpResponse.setUserDetail("NULL", null, "NULL"); // added
		cpResponse.setUserDetails("NULL", null, List.of());
		assertThat(cpResponse.getUserDetails()
							 .size(), is(2));
		cpResponse.setUserDetail("attr1", "attr1-long", "value1");
		cpResponse.setUserDetails("attr1", "attr1-long", List.of("value2", "value3"));
		assertThat(cpResponse.getUserDetails()
							 .size(), is(3));
		assertThat(cpResponse.getUserDetails("attr1"), contains("value2", "value3"));
		assertThat(cpResponse.getUserDetail("attr1"), is("value2"));
		assertThat(cpResponse.getUserDetail("attr2"), is(nullValue()));

		// add
		cpResponse.addUserDetail("attr1", "attr1-long", "value4");
		assertThat(cpResponse.getUserDetails("attr1"), contains("value2", "value3", "value4"));
		cpResponse.addUserDetail("attr2", "attr2-long", "value2");
		cpResponse.addUserDetail("attr2", "attr2-long", "added");
		cpResponse.addUserDetailIfMissing("attr2", "attr2-long", "dropped");
		cpResponse.addUserDetailIfMissing("attr2", "attr2-long", "ignored");
		assertThat(cpResponse.getUserDetails("attr2"), contains("value2", "added"));

		// remove
		cpResponse.removeUserDetails("attr1");
		assertThat(cpResponse.getUserDetail("attr1"), is(nullValue()));
		assertThat(cpResponse.getUserDetail("attr2"), is("value2"));
	}

	@Test
	void testDerivedAttributes() {
		// set/get
		var cpResponse = new CpResponse();
		cpResponse.setProperty(null, null, null);
		cpResponse.setProperty(null, null, "NULL");
		cpResponse.setProperty(null, "NULL", null);
		cpResponse.setProperty(null, "NULL", "NULL"); // added
		cpResponse.setProperty("NULL", null, null);
		cpResponse.setProperty("NULL", null, "NULL"); // added
		cpResponse.setProperties("NULL", null, List.of());
		assertThat(cpResponse.getProperties()
							 .size(), is(2));
		cpResponse.setProperty("attr1", "attr1-long", "value1");
		cpResponse.setProperties("attr1", "attr1-long", List.of("value2", "value3"));
		assertThat(cpResponse.getProperties()
							 .size(), is(3));
		assertThat(cpResponse.getProperties("attr1"), contains("value2", "value3"));
		assertThat(cpResponse.getProperty("attr1"), is("value2"));
		assertThat(cpResponse.getProperty("attr2"), is(nullValue()));

		// add
		cpResponse.addProperty("attr1", "attr1-long", "value4");
		assertThat(cpResponse.getProperties("attr1"), contains("value2", "value3", "value4"));
		cpResponse.addProperty("attr2", "attr2-long", "value2");
		cpResponse.addProperty("attr2", "attr2-long", "added");
		cpResponse.addPropertyIfMissing("attr2", "attr2-long", "dropped");
		cpResponse.addPropertyIfMissing("attr2", "attr2-long", "ignored");
		assertThat(cpResponse.getProperties("attr2"), contains("value2", "added"));

		// remove
		cpResponse.removeProperty("attr1");
		assertThat(cpResponse.getProperty("attr1"), is(nullValue()));
		assertThat(cpResponse.getProperty("attr2"), is("value2"));
	}

	@Test
	@SuppressWarnings("unchecked")
	void testClaims() {
		// set/get
		var cpResponse = new CpResponse();
		cpResponse.setClaim(null, null);
		cpResponse.setClaim(null, "NULL");
		cpResponse.setClaim("NULL", null);
		cpResponse.setClaim("NULL", List.of());
		assertThat(cpResponse.getClaims()
							 .size(), is(0));
		cpResponse.setClaim("attr1", "value1");
		cpResponse.setClaims("attr1", List.of("value2", "value3"));
		assertThat(cpResponse.getClaims()
							 .size(), is(1));
		assertThat((List<String>) cpResponse.getClaims("attr1"), contains("value2", "value3"));
		assertThat(cpResponse.getClaim("attr1"), is("value2"));
		assertThat(cpResponse.getClaim("attr2"), is(nullValue()));

		// add
		cpResponse.addClaim("attr1", "value4");
		assertThat((List<String>) cpResponse.getClaims("attr1"), contains("value2", "value3", "value4"));
		cpResponse.addClaim("attr2", "value2");
		assertThat((List<String>) cpResponse.getClaims("attr2"), contains("value2"));

		// remove
		cpResponse.removeClaim("attr1");
		assertThat(cpResponse.getClaim("attr1"), is(nullValue()));
		assertThat(cpResponse.getClaim("attr2"), is("value2"));
	}


}
