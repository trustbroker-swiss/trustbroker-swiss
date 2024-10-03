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
import static org.hamcrest.Matchers.is;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.SubjectName;
import swiss.trustbroker.federation.xmlconfig.SubjectNameMappings;
import swiss.trustbroker.saml.dto.CpResponse;

class SubjectNameMapperTest {

	@Test
	void adjustSubjectNameId() {
		var expectedSubjectNameIdFrom = CoreAttributeName.EMAIL.getNamespaceUri();
		var cpIssuer = "cpIssuer1";
		var subjectNameMappings =
				SubjectNameMappings.builder()
								   .preserve(true)
								   .subjects(List.of(
										   SubjectName.builder()
													  .issuer(cpIssuer) // mapped if from this CP
													  .source(expectedSubjectNameIdFrom)
													  .format("from-config-0")
													  .build(),
										   SubjectName.builder()
													  .issuer(null) // mapped from any CP
													  .source("source-without-value")
													  .format("from-config-1")
													  .build(),
										   SubjectName.builder()
													  .issuer("cpIssuer2")
													  .issuer(null)
													  .source(expectedSubjectNameIdFrom)
													  .format("from-config-2")
													  .build())
								   )
								   .build();
		var relyingParty = RelyingParty.builder()
									   .id("rpIssuer1")
									   .subjectNameMappings(subjectNameMappings)
									   .build();
		var userDetails = Map.of(Definition.builder()
										   .name("anyAuditName")
										   .namespaceUri(expectedSubjectNameIdFrom)
										   .build(), List.of("me@trustbroker.swiss"));
		// modified and logged
		var cpResponse0 = CpResponse.builder()
									.issuer("cpIssuer1")
									.originalNameId("initial")
									.nameId("initial")
									.nameIdFormat("from-idp")
									.userDetails(userDetails)
									.build();
		SubjectNameMapper.adjustSubjectNameId(cpResponse0, relyingParty);
		assertThat(cpResponse0.getNameId(), is("me@trustbroker.swiss"));
		assertThat(cpResponse0.getNameIdFormat(), is("from-config-0"));

		// not modified as already manipulated but preserving message is logged
		var cpResponse1 = CpResponse.builder()
									.issuer("cpIssuer2")
									.originalNameId("initial")
									.nameId("modified-by-groovy-hook")
									.nameIdFormat("from-idp")
									.userDetails(userDetails)
									.build();
		SubjectNameMapper.adjustSubjectNameId(cpResponse1, relyingParty);
		assertThat(cpResponse1.getNameId(), is("modified-by-groovy-hook"));
		assertThat(cpResponse1.getNameIdFormat(), is("from-idp"));
	}

}