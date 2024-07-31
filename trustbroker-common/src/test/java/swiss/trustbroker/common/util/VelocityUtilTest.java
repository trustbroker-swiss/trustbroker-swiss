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

import java.util.Map;

import org.apache.velocity.VelocityContext;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletResponse;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.VelocityUtil;

class VelocityUtilTest {

	@Test
	void populateVelocityContext() {
		var data = Map.of("key1", "value1", "key2", "value2");
		var context = new VelocityContext();

		VelocityUtil.populateVelocityContext(context, data);

		for (var entry : data.entrySet()) {
			assertThat(context.get(entry.getKey()), is(entry.getValue()));
		}
	}

	@Test
	void renderTemplate() throws Exception {
		var engine = OpenSamlUtil.createVelocityEngine(null);
		var response = new MockHttpServletResponse();
		var data = Map.of("key1", "value1", "key2", "value2");

		VelocityUtil.renderTemplate(engine, response, "/templates/Template.vm", data);

		assertThat(response.getContentAsString(), is("One: value1\nTwo: value2"));
	}

}
