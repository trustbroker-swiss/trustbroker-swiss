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

package swiss.trustbroker.federation.xmlconfig;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import org.junit.jupiter.api.Test;

class ClaimsPartyTest {

	@Test
	void isDelegateOrigin() {
		var cp = ClaimsParty.builder().build();
		assertThat(cp.isDelegateOrigin(), is(false));
		var secPol = SecurityPolicies.builder().build();
		cp.setSecurityPolicies(secPol);
		assertThat(cp.isDelegateOrigin(), is(false));
		secPol.setDelegateOrigin(true);
		assertThat(cp.isDelegateOrigin(), is(true));
	}

	@Test
	void getOriginalIssuer() {
		var cpId = "cpId1";
		var cp = ClaimsParty.builder().id(cpId).build();
		assertThat(cp.getOriginalIssuer(), is(cpId));
		var origIssuer = "cpId2";
		cp.setOriginalIssuer(origIssuer);
		assertThat(cp.getOriginalIssuer(), is(origIssuer));
	}

}
