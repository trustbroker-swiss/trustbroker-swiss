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

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.apache.commons.beanutils.BeanUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.common.saml.util.SamlContextClass;
import swiss.trustbroker.federation.xmlconfig.AcClass;
import swiss.trustbroker.federation.xmlconfig.AcWhitelist;
import swiss.trustbroker.federation.xmlconfig.AccessRequest;
import swiss.trustbroker.federation.xmlconfig.AttributesSelection;
import swiss.trustbroker.federation.xmlconfig.AuthorizationGrantType;
import swiss.trustbroker.federation.xmlconfig.AuthorizationGrantTypes;
import swiss.trustbroker.federation.xmlconfig.AuthorizedApplication;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderMappings;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderRelyingParty;
import swiss.trustbroker.federation.xmlconfig.ClientAuthenticationMethod;
import swiss.trustbroker.federation.xmlconfig.ClientAuthenticationMethods;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.Oidc;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.OidcSecurityPolicies;
import swiss.trustbroker.federation.xmlconfig.Qoa;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.Scopes;

class RelyingPartySetupUtilTest {

	@Test
	void mergeClaimsProviderMappings() {
		var profileClaimsProviderMappings = ClaimsProviderMappings
				.builder()
				.claimsProviderList(List.of(
						ClaimsProviderRelyingParty.builder()
												  .id("P1enabled")
												  .enabled(true)
												  .order(100)
												  .clientNetworks("N1,N2")
												  .build(),
						ClaimsProviderRelyingParty.builder()
												  .id("P2disabled")
												  .enabled(false)
												  .order(200)
												  .clientNetworks("N1,N2")
												  .build(),
						ClaimsProviderRelyingParty.builder()
												  .id("P3network")
												  .enabled(false)
												  .order(300)
												  .clientNetworks("N1,N2")
												  .build()
				))
				.build();
		var claimsProviderMappings = ClaimsProviderMappings
				.builder()
				.claimsProviderList(List.of(
						ClaimsProviderRelyingParty.builder()
												  .id("P1enabled")
												  .relyingPartyAlias("alias1")
												  .build(),
						ClaimsProviderRelyingParty.builder()
												  .id("P2disabled")
												  .enabled(false)
												  .build(),
						ClaimsProviderRelyingParty.builder()
												  .id("P3network")
												  .enabled(true)
												  .clientNetworks("N3")
												  .build(),
						ClaimsProviderRelyingParty.builder()
												  .id("R1enabled")
												  .enabled(true)
												  .order(1)
												  .clientNetworks("N4")
												  .build(),
						ClaimsProviderRelyingParty.builder()
												  .id("R2disabled")
												  .enabled(false)
												  .order(999)
												  .build()
				))
				.build();
		var relyingParty = RelyingParty
				.builder()
				.id("TestRP")
				.base("ProfileRP")
				.claimsProviderMappings(claimsProviderMappings)
				.build();

		RelyingPartySetupUtil.mergeClaimsProviderMappings(relyingParty, profileClaimsProviderMappings);

		// all enabled CPs from profile and setup were combined with overrides from setup, no disabled ones anymore
		var mappings = relyingParty.getClaimsProviderMappings();
		assertThat(mappings, is(notNullValue()));
		var mappingList = relyingParty.getClaimsProviderMappings().getClaimsProviderList();
		assertThat(mappingList, is(notNullValue()));
		assertThat(mappingList.size(), is(4));
		// SetupRP with alias copied
		assertThat(mappingList.get(0).getId(), is("P1enabled"));
		assertThat(mappingList.get(0).getClientNetworks(), is(nullValue()));
		assertThat(mappingList.get(0).getRelyingPartyAlias(), is("alias1"));
		assertThat(mappingList.get(0).getEnabled(), is(nullValue())); // null is treated as enabled
		assertThat(mappingList.get(0).getOrder(), is(nullValue())); // null is treated as not relevant to clients
		// ProfileRP merged
		assertThat(mappingList.get(1).getId(), is("P3network"));
		assertThat(mappingList.get(1).getEnabled(), is(true));
		assertThat(mappingList.get(1).getOrder(), is(300));
		assertThat(mappingList.get(1).getClientNetworks(), is("N3"));
		assertThat(mappingList.get(1).getRelyingPartyAlias(), is(nullValue()));
		// SetupRP copied
		assertThat(mappingList.get(2).getId(), is("R1enabled"));
		assertThat(mappingList.get(2).getClientNetworks(), is("N4"));
		assertThat(mappingList.get(2).getRelyingPartyAlias(), is(nullValue()));
		assertThat(mappingList.get(2).getEnabled(), is(true));
		assertThat(mappingList.get(2).getOrder(), is(1));
		// ProfileRP added
		assertThat(mappingList.get(3).getId(), is("P1enabled"));
		assertThat(mappingList.get(3).getEnabled(), is(true));
		assertThat(mappingList.get(3).getOrder(), is(100));
		assertThat(mappingList.get(3).getClientNetworks(), is("N1,N2"));
		assertThat(mappingList.get(3).getRelyingPartyAlias(), is(nullValue()));
	}

	@Test
	void mergeAccessRequestCopy() {
		var profile = createRelyingPartyWithAccessRequest();
		var rp = RelyingParty.builder().id("rp1").build();

		RelyingPartySetupUtil.mergeAccessRequest(rp, profile);

		assertThat(rp.getAccessRequest(), sameInstance(profile.getAccessRequest()));
	}

	@Test
	void mergeAccessRequestCopyApplication() {
		var profile = createRelyingPartyWithAccessRequest();
		var templateApp = AuthorizedApplication.builder().name("app1").build();
		profile.getAccessRequest().getAuthorizedApplications().getAuthorizedApplicationLists().add(templateApp);
		var rp = createRelyingPartyWithAccessRequest();

		RelyingPartySetupUtil.mergeAccessRequest(rp, profile);

		assertThat(rp.getAccessRequest().getAuthorizedApplications().getAuthorizedApplicationLists().size(), is(1));
		assertThat(rp.getAccessRequest().getAuthorizedApplications().getAuthorizedApplicationLists().get(0),
				sameInstance(templateApp));
	}

	@Test
	void mergeAccessRequestDuplicateDefault() {
		var profile = createRelyingPartyWithAccessRequest();
		var rp = createRelyingPartyWithAccessRequest();
		var defaultAppName = "defaultApp";
		var defaultApp = AuthorizedApplication.builder().name(defaultAppName).build();
		rp.getAccessRequest().getAuthorizedApplications().getAuthorizedApplicationLists().add(defaultApp);
		var otherDefaultAppName = "otherDefaultApp";
		var otherDefaultApp = AuthorizedApplication.builder().name(otherDefaultAppName).build();
		rp.getAccessRequest().getAuthorizedApplications().getAuthorizedApplicationLists().add(otherDefaultApp);

		var ex = assertThrows(TechnicalException.class, () -> RelyingPartySetupUtil.mergeAccessRequest(rp, profile));

		assertThat(ex.getInternalMessage(), containsString(defaultAppName));
		assertThat(ex.getInternalMessage(), containsString(otherDefaultAppName));
	}

	@Test
	void mergeAccessRequest() {
		var profile = createRelyingPartyWithAccessRequest();
		profile.getAccessRequest().setEnabled(false);
		var mode = "SILENT";
		var url = "https://localhost/silent";
		var templateApp = AuthorizedApplication.builder().mode(mode).serviceUrl(url).build();
		profile.getAccessRequest().getAuthorizedApplications().getAuthorizedApplicationLists().add(templateApp);

		var rp = createRelyingPartyWithAccessRequest();
		// one retained and one merged attribute each to ensure both are updated
		var app1Name = "app1";
		var url1 = "https://localhost/silent2";
		var app1 = AuthorizedApplication.builder().name(app1Name).serviceUrl(url1).build();
		rp.getAccessRequest().getAuthorizedApplications().getAuthorizedApplicationLists().add(app1);
		var app2Name = "app2";
		var mode2 = "INTERACTIVE";
		// set URL for second one, there must be only one default
		var app2 = AuthorizedApplication.builder().name(app2Name).url("/url").mode(mode2).build();
		rp.getAccessRequest().getAuthorizedApplications().getAuthorizedApplicationLists().add(app2);

		RelyingPartySetupUtil.mergeAccessRequest(rp, profile);

		assertThat(rp.getAccessRequest().getEnabled(), is(Boolean.TRUE)); // not copied

		var apps = rp.getAccessRequest().getAuthorizedApplications();
		assertThat(apps.getAuthorizedApplicationLists().size(), is(2));

		var mergedApp1 = apps.getAuthorizedApplicationLists().get(0);
		assertThat(mergedApp1.getName(), is(app1Name));
		assertThat(mergedApp1.getMode(), is(mode));
		assertThat(mergedApp1.getServiceUrl(), is(url1));

		var mergedApp2 = apps.getAuthorizedApplicationLists().get(1);
		assertThat(mergedApp2.getName(), is(app2Name));
		assertThat(mergedApp2.getMode(), is(mode2));
		assertThat(mergedApp2.getServiceUrl(), is(url));
	}

	@ParameterizedTest
	@CsvSource(value = { "true", "false" })
	void mergeAccessRequestWrongTemplate(boolean enabled) {
		var profile = createRelyingPartyWithAccessRequest();
		profile.getAccessRequest().getAuthorizedApplications().getAuthorizedApplicationLists()
				.add(AuthorizedApplication.builder().build());
		profile.getAccessRequest().getAuthorizedApplications().getAuthorizedApplicationLists()
				.add(AuthorizedApplication.builder().build());

		var rp = createRelyingPartyWithAccessRequest();
		rp.getAccessRequest().setEnabled(enabled);

		if (enabled) {
			assertThrows(TechnicalException.class, () -> RelyingPartySetupUtil.mergeAccessRequest(rp, profile));
		}
		else {
			assertDoesNotThrow(() -> RelyingPartySetupUtil.mergeAccessRequest(rp, profile));
		}
	}

	@Test
	void mergeAccessRequestOidc() {
		var profile = createRelyingPartyWithAccessRequest();
		var rp = createRelyingPartyWithAccessRequest();
		rp.getAccessRequest().getAuthorizedApplications().getAuthorizedApplicationLists()
				.add(AuthorizedApplication.builder().name("test1").build());
		rp.getAccessRequest().getAuthorizedApplications().getAuthorizedApplicationLists()
				.add(AuthorizedApplication.builder().name("test2").build());
		rp.setOidc(Oidc.builder().clients(List.of(OidcClient.builder().build())).build());

		assertDoesNotThrow(() -> RelyingPartySetupUtil.mergeAccessRequest(rp, profile));
	}

	@Test
	void mergeQoaLevelsTest() {
		// empty
		var relyingParty = new RelyingParty();
		var baseRelyingParty = new RelyingParty();
		assertDoesNotThrow(() -> RelyingPartySetupUtil.mergeQoaLevels(relyingParty, baseRelyingParty));

		// base profile
		var expectedQoa = givenQoa(null, SamlContextClass.MOBILE_ONE_FACTOR_UNREGISTERED);
		baseRelyingParty.setQoa(expectedQoa);
		RelyingPartySetupUtil.mergeQoaLevels(relyingParty, baseRelyingParty);
		var actualQoa = relyingParty.getQoa();
		assertThat(actualQoa, is(expectedQoa));

		// preserve
		baseRelyingParty.setQoa(givenQoa(2, SamlContextClass.SMART_CARD_PKI));
		RelyingPartySetupUtil.mergeQoaLevels(relyingParty, baseRelyingParty);
		assertThat(relyingParty.getQoa(), is(expectedQoa));
	}

	@Test
	void notInBaseOrHasOidcConfTest() {
		List<Definition> baseAttributes = givenDefinitionList();
		List<Definition> toRemove;

		// NOT in Base
		Definition definition = Definition.builder()
				.name(CoreAttributeName.FIRST_NAME.getName())
				.namespaceUri(CoreAttributeName.FIRST_NAME.getNamespaceUri())
				.build();
		toRemove = new ArrayList<>();
		assertTrue(RelyingPartySetupUtil.notInBaseOrHasOidcConf(baseAttributes, definition, toRemove));
		assertEquals(0, toRemove.size());

		// In Base, no OIDC attribute
		definition = Definition.builder()
				.name(CoreAttributeName.NAME.getName())
				.namespaceUri(CoreAttributeName.NAME.getNamespaceUri())
				.build();
		assertFalse(RelyingPartySetupUtil.notInBaseOrHasOidcConf(baseAttributes, definition, toRemove));

		// In Base, OIDC attribute in SetupRP conf
		definition = Definition.builder()
				.name(CoreAttributeName.NAME.getName())
				.namespaceUri(CoreAttributeName.NAME.getNamespaceUri())
				.oidcNames("oidcname")
				.scope("scope")
				.build();
		toRemove = new ArrayList<>();
		assertTrue(RelyingPartySetupUtil.notInBaseOrHasOidcConf(baseAttributes, definition, toRemove));
		assertFalse(toRemove.isEmpty());

		// In Base, only OIDC name attribute in SetupRP conf
		definition = Definition.builder()
				.name(CoreAttributeName.NAME.getName())
				.namespaceUri(CoreAttributeName.NAME.getNamespaceUri())
				.oidcNames("oidcname")
				.build();
		toRemove = new ArrayList<>();
		assertTrue(RelyingPartySetupUtil.notInBaseOrHasOidcConf(baseAttributes, definition, toRemove));
		assertFalse(toRemove.isEmpty());

		// In Base, OIDC name attribute in Profile and in SetupRP conf
		definition = Definition.builder()
				.name(CoreAttributeName.EMAIL.getName())
				.namespaceUri(CoreAttributeName.EMAIL.getNamespaceUri())
				.oidcNames("oidcname")
				.build();
		toRemove = new ArrayList<>();
		assertFalse(RelyingPartySetupUtil.notInBaseOrHasOidcConf(baseAttributes, definition, toRemove));


		// In Base, OIDC name attribute only in Profile
		definition = Definition.builder()
				.name(CoreAttributeName.EMAIL.getName())
				.namespaceUri(CoreAttributeName.EMAIL.getNamespaceUri())
				.build();
		toRemove = new ArrayList<>();
		assertFalse(RelyingPartySetupUtil.notInBaseOrHasOidcConf(baseAttributes, definition, toRemove));
	}

	@Test
	void definitionInListTest() {
		List<Definition> definitionList = givenDefinitionList();

		Definition definition = Definition.builder()
				.name(CoreAttributeName.NAME.getName())
				.namespaceUri(CoreAttributeName.NAME.getNamespaceUri())
				.build();
		assertTrue(RelyingPartySetupUtil.definitionInList(definition, definitionList).isPresent());

		// Same attribute but no oidc name => present
		definition = Definition.builder()
				.name(CoreAttributeName.EMAIL.getName())
				.namespaceUri(CoreAttributeName.EMAIL.getNamespaceUri())
				.build();
		assertTrue(RelyingPartySetupUtil.definitionInList(definition, definitionList).isPresent());


		definition = Definition.builder()
				.name(CoreAttributeName.FIRST_NAME.getName())
				.namespaceUri(CoreAttributeName.FIRST_NAME.getNamespaceUri())
				.build();
		assertThat(RelyingPartySetupUtil.definitionInList(definition, definitionList), is(Optional.empty()));

		definition = Definition.builder()
				.name(CoreAttributeName.NAME_ID.getName())
				.namespaceUri(CoreAttributeName.FIRST_NAME.getNamespaceUri())
				.build();
		assertThat(RelyingPartySetupUtil.definitionInList(definition, definitionList), is(Optional.empty()));
	}

	@Test
	void oidcClientMergeTest() throws InvocationTargetException, IllegalAccessException {
		var defsBase = givenDefinitionList();
		var defsExpected = givenDefinitionList();
		var defsClientAddon = Definition.builder().name("ClientAddOnClaim").build();
		defsExpected.add(defsClientAddon);

		var client = OidcClient.builder()
				.id("OidcTestClient")
				.federationId("Saml.IssuerId")
				.clientSecret("per client")
				// aggregate
				.redirectUris(AcWhitelist.builder().acUrls(new ArrayList<>(List.of("url1", "url2"))).build())
				.claimsSelection(AttributesSelection.builder().definitions(new ArrayList<>(List.of(
						Definition.builder().name("ClientAddOnClaim").build()))).build())
				.oidcSecurityPolicies(OidcSecurityPolicies.builder()
						.requireProofKey(true)
						.requireAuthorizationConsent(false)
						.tokenTimeToLiveMin(480) // 28800sec SAML assertion TTL
						.refreshTokenTimeToLiveMin(60) // 3600sec SAML response TTL (see application.yml)
						.build())
				// stuff overwritten
				.scopes(Scopes.builder().scopeList(List.of("openid", "email", "profile", "address", "phone")).build())
				.qoa(Qoa.builder().classes(List.of(AcClass.builder().contextClass("qoa10").build())).build())
				.build();
		var base = OidcClient.builder()
				.redirectUris(AcWhitelist.builder().acUrls(List.of("url3", "url4")).build())
				.claimsSelection(AttributesSelection.builder().definitions(defsBase).build())
				.oidcSecurityPolicies(OidcSecurityPolicies.builder()
						.build())
				.scopes(Scopes.builder()
						.scopeList(List.of("lost")).build())
				.authorizationGrantTypes(AuthorizationGrantTypes.builder()
						.grantTypes(
								List.of(AuthorizationGrantType.AUTHORIZATION_CODE,
										AuthorizationGrantType.REFRESH_TOKEN)
						).build())
				.clientAuthenticationMethods(ClientAuthenticationMethods.builder()
						.methods(
								List.of(ClientAuthenticationMethod.NONE,
										ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
										ClientAuthenticationMethod.CLIENT_SECRET_POST)
						).build())
				.qoa(Qoa.builder().classes(List.of(AcClass.builder().contextClass("lost").build())).build())
				.build();

		RelyingPartySetupUtil.mergeOidcClient(client, base);

		var expected = OidcClient.builder().build();
		BeanUtils.copyProperties(expected, client);
		expected.getRedirectUris().getAcUrls().addAll(base.getRedirectUris().getAcUrls());
		expected.getClaimsSelection().getDefinitions().addAll(base.getClaimsSelection().getDefinitions());

		assertThat(client, is(expected));
		assertThat(client.getRedirectUris().getAcUrls(), containsInAnyOrder("url1", "url2", "url3", "url4"));
		assertThat(client.getClaimsSelection().getDefinitions(), containsInAnyOrder(defsExpected.toArray()));
	}

	private List<Definition> givenDefinitionList() {
		List<Definition> definitions = new ArrayList<>();
		definitions.add(Definition.builder()
				.name(CoreAttributeName.NAME.getName())
				.namespaceUri(CoreAttributeName.NAME.getNamespaceUri())
				.build());
		definitions.add(Definition.builder()
				.name(CoreAttributeName.EMAIL.getName())
				.namespaceUri(CoreAttributeName.EMAIL.getNamespaceUri())
				.oidcNames("email")
				.build());
		definitions.add(Definition.builder()
				.name(CoreAttributeName.CLAIMS_NAME.getName())
				.namespaceUri(CoreAttributeName.CLAIMS_NAME.getNamespaceUri())
				.oidcNames("claimsname")
				.scope("oidc")
				.build());
		definitions.add(Definition.builder()
				.name(CoreAttributeName.NAME_ID.getName())
				.namespaceUri(CoreAttributeName.NAME_ID.getNamespaceUri())
				.build());
		return definitions;
	}

	private Qoa givenQoa(Integer order, String qoaClass) {
		List<AcClass> classes = new ArrayList<>();
		classes.add(AcClass.builder().order(order).contextClass(qoaClass).build());
		Qoa qoa = new Qoa();
		qoa.setClasses(classes);
		return qoa;
	}

	private static RelyingParty createRelyingPartyWithAccessRequest() {
		var ar = AccessRequest.builder().enabled(true).build();
		return RelyingParty.builder().id("rpId").accessRequest(ar).build();
	}

}
