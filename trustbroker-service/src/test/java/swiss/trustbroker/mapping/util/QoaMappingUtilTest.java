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

package swiss.trustbroker.mapping.util;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.SamlContextClass;
import swiss.trustbroker.config.dto.QualityOfAuthenticationConfig;
import swiss.trustbroker.federation.xmlconfig.AcClass;
import swiss.trustbroker.federation.xmlconfig.Qoa;
import swiss.trustbroker.federation.xmlconfig.QoaComparison;
import swiss.trustbroker.mapping.dto.QoaConfig;
import swiss.trustbroker.test.saml.util.SamlTestBase;

@SpringBootTest
@ContextConfiguration(classes = QoaMappingUtil.class)
class QoaMappingUtilTest {

	private static final String ISSUER = "issuer1";

	@ParameterizedTest
	@CsvSource(value = {
			"true,true,true",
			"true,false,true",
			"false,false,false",
	}, nullValues = "null")
	void invalidQoaExceptionTest(boolean cpEnforce, boolean rpEnforce, boolean throwEx) {
		List<String> requestCtxClasses = Arrays.asList("class1", "class2");
		var cpQoa = Qoa.builder().enforce(cpEnforce).build();
		var cpQoaConfig = new QoaConfig(cpQoa, "12345");
		var rpQoa = Qoa.builder().enforce(rpEnforce).build();
		var rpQoaConf = new QoaConfig(rpQoa, "rpId");
		List<String> expectedCtxClasses = List.of("class1", "class2", "class3");

		if (throwEx) {
			assertThrows(RequestDeniedException.class, () ->
					QoaMappingUtil.invalidQoaException(QoaComparison.MINIMUM, requestCtxClasses, expectedCtxClasses,
							cpQoaConfig, rpQoaConf)
			);
		}
		else {
			assertDoesNotThrow(() ->
					QoaMappingUtil.invalidQoaException(QoaComparison.MINIMUM, requestCtxClasses, expectedCtxClasses,
							cpQoaConfig, rpQoaConf)
			);
		}
	}

	@Test
	void invalidQoaExceptionNoConfigTest() {
		assertDoesNotThrow(() ->
				QoaMappingUtil.invalidQoaException(QoaComparison.MINIMUM, null, null,
						new QoaConfig(null, "12345"), new QoaConfig(null, "rpId"))
		);
	}

	@Test
	void getConfigAcClassesTest() {
		var configQoa  = Qoa.builder().build();

		assertThat("Expected null when configQoa is null.",
				QoaMappingUtil.getConfigAcClasses("class1", null, null), is(empty()));
		assertThat( "Expected null when configQoa has an empty class list.",
				QoaMappingUtil.getConfigAcClasses("class1", configQoa, null), is(empty()));

		var outbound1 = "outbound1";
		var outboundOnly = AcClass.builder().mapInbound(false).contextClass(outbound1).build();
		var inbound1 = "inbound1";
		var inboundOnly = AcClass.builder().mapOutbound(false).order(20).contextClass(inbound1).build();
		var acClass3 = AcClass.builder().build();
		var inboundOnly2 = AcClass.builder().mapOutbound(false).order(10).contextClass(inbound1).build();
		configQoa.setClasses(List.of(outboundOnly, inboundOnly, acClass3, inboundOnly2));

		// direction not set
		var result = QoaMappingUtil.getConfigAcClasses(outbound1, configQoa, null);
		assertEquals(List.of(outboundOnly), result, "Expected the correct ACClass object to be returned.");
		result = QoaMappingUtil.getConfigAcClasses(inbound1, configQoa, null);
		assertEquals(List.of(inboundOnly, inboundOnly2), result, "Expected the correct ACClass object to be returned.");
		result = QoaMappingUtil.getConfigAcClasses("class3", configQoa, null);
		assertThat("Expected null when no matching contextClass is found.", result, is(empty()));

		// outbound
		result = QoaMappingUtil.getConfigAcClasses(outbound1, configQoa, true);
		assertEquals(List.of(outboundOnly), result, "Expected the correct outbound ACClass object to be returned.");
		result = QoaMappingUtil.getConfigAcClasses(inbound1, configQoa, true);
		assertThat("Expected null for matching inbound ACClass object on outbound.", result, is(empty()));

		// inbound
		result = QoaMappingUtil.getConfigAcClasses(outbound1, configQoa, false);
		assertThat("Expected null for matching outbound ACClass object on inbound.", result, is(empty()));
		result = QoaMappingUtil.getConfigAcClasses(inbound1, configQoa, false);
		assertEquals(List.of(inboundOnly, inboundOnly2), result, "Expected the correct inbound ACClass object to be returned.");
	}

	@Test
	void isKnownQoaLevelsTest() {
		List<String> requestContextClasses = new ArrayList<>();
		var acClass1 = AcClass.builder().order(40).contextClass("class40").build();
		var qoa  = Qoa.builder().enforce(true).classes(List.of(acClass1)).build();
		var configQoa = new QoaConfig(qoa, "12345");
		Map<String, Integer> globalMapping = givenGlobalQoa().getMapping();

		QoaMappingUtil.isKnownQoaLevels(requestContextClasses, configQoa, globalMapping, null);

		// qoa is in Global and order matches the config
		requestContextClasses.add(SamlTestBase.Qoa.KERBEROS.getName());
		QoaMappingUtil.isKnownQoaLevels(requestContextClasses, configQoa, globalMapping, null);

		// qoa is in global but no matching config order
		requestContextClasses.add(SamlTestBase.Qoa.SOFTWARE_PKI.getName());
		assertThrows(TechnicalException.class, () ->
				QoaMappingUtil.isKnownQoaLevels(requestContextClasses, configQoa, globalMapping, null)
		);
	}

	@Test
	void getConfigAcClassesByOrdersTest() {
		var acClass1 = AcClass.builder().order(40).contextClass("class40").build();
		List<AcClass> acClasses = new ArrayList<>();
		acClasses.add(acClass1);
		var qoa  = Qoa.builder().enforce(true).classes(acClasses).build();
		var configQoa = new QoaConfig(qoa, ISSUER);
		Map<String, Integer> globalMapping = givenGlobalQoa().getMapping();

		assertThat("Expected an empty result when order is null.",
				QoaMappingUtil.getConfigAcClassesByOrders(configQoa, Collections.emptySet(), globalMapping, false),
				is(empty()));
		assertThat("Expected an empty result when qoa is null.",
				QoaMappingUtil.getConfigAcClassesByOrders(new QoaConfig(null, ISSUER), Set.of(1), globalMapping, false),
				is(empty()));

		acClass1.setOrder(10);
		assertThat("Expected an empty result when no matching order is found.",
				QoaMappingUtil.getConfigAcClassesByOrders(configQoa, Set.of(1), globalMapping, false),
				is(empty()));

		var acClass2 = AcClass.builder().order(2).contextClass("class2").build();
		qoa.getClasses().add(acClass2);
		assertThat("Expected the correct matching class.",
				QoaMappingUtil.getConfigAcClassesByOrders(configQoa, Set.of(1, 2), globalMapping, false),
				is(List.of(acClass2)));

		var acClassInbound = AcClass.builder().order(3).contextClass("inboundOnly").mapOutbound(false).build();
		qoa.getClasses().add(acClassInbound);
		var acClassOutbound = AcClass.builder().order(3).contextClass("outboundOnly").mapInbound(false).build();
		qoa.getClasses().add(acClassOutbound);
		var acClass3 = AcClass.builder().order(3).contextClass("class3").build();
		qoa.getClasses().add(acClass3);
		var qoaConfig = new QoaConfig(qoa, ISSUER);
		assertThat("Expected all matching classes with inbound mapping to be returned.",
				QoaMappingUtil.getConfigAcClassesByOrders(qoaConfig, Set.of(2, 3), globalMapping, false),
				is(List.of(acClass2, acClassInbound, acClass3)));
		assertThat("Expected all matching classes with outbound mapping to be returned.",
				QoaMappingUtil.getConfigAcClassesByOrders(qoaConfig, Set.of(2, 3), globalMapping, true),
				is(List.of(acClass2, acClassOutbound, acClass3)));
	}

	@Test
	void getQoasByLevelsTest() {
		Map<String, Integer> globalMapping = new HashMap<>();
		assertThat("Expected an empty list when the map is empty.",
				QoaMappingUtil.getQoasByLevels(Set.of(1), globalMapping),
				is(empty()));

		globalMapping = givenGlobalQoa().getMapping();
		assertThat("Expected an empty list when no keys match the specified level.",
				QoaMappingUtil.getQoasByLevels(Set.of(1), globalMapping),
				is(empty()));

		assertThat("Expected KERBEROS to be in the result.",
				QoaMappingUtil.getQoasByLevels(Set.of(40), globalMapping),
				is(List.of(SamlTestBase.Qoa.KERBEROS.getName())));

		assertThat("Expected KERBEROS to be in the result.",
				QoaMappingUtil.getQoasByLevels(Set.of(40, 50), globalMapping),
				containsInAnyOrder(SamlTestBase.Qoa.KERBEROS.getName(), SamlTestBase.Qoa.SOFTWARE_PKI.getName()));
	}

	@ParameterizedTest
	@MethodSource
	void validateQoaComparisonTest(Set<Integer> orders, QoaComparison comparisonType, boolean expected) {
		var cpQoa  = Qoa.builder().enforce(true).build();
		var cpQoaConfig = new QoaConfig(cpQoa, "REQ123");
		Set<Integer> reqQoaOrders = Set.of(1, 2, 3);

		assertThat(QoaMappingUtil.validateQoaComparison(cpQoaConfig, comparisonType, reqQoaOrders, orders), is(expected));
	}

	static Object[][] validateQoaComparisonTest() {
		return new Object[][] {
				{ Set.of(2), QoaComparison.EXACT, true },
				{ Set.of(3, 4), QoaComparison.EXACT, true },
				{ Set.of(4), QoaComparison.EXACT, false },
				{ Set.of(2), QoaComparison.MINIMUM, true },
				{ Set.of(0), QoaComparison.MINIMUM, false },
				{ Set.of(3), QoaComparison.MAXIMUM, true },
				{ Set.of(4), QoaComparison.MAXIMUM, false },
				{ Set.of(4), QoaComparison.BETTER, true },
				{ Set.of(1), QoaComparison.BETTER, false },
				{ Set.of(2), null, false },
		};
	}

	@Test
	void validateQoaComparisonEmptyOrderTest() {
		var cpQoa  = Qoa.builder().enforce(true).build();
		var cpQoaConfig = new QoaConfig(cpQoa, "REQ123");

		assertThat(QoaMappingUtil.validateQoaComparison(cpQoaConfig, QoaComparison.MINIMUM, Set.of(),  Set.of(2)), is(true));
	}

	@Test
	void validateCpContextClassesTest() {
		List<String> contextClasses = List.of("ClassA", "ClassB");
		var requestClassRef = "ClassA";
		var comparison = QoaComparison.EXACT;
		var cpQoa  = Qoa.builder().enforce(true).build();
		var cpQoaConf = new QoaConfig(cpQoa, "REQ123");
		var rpQoa  = Qoa.builder().enforce(true).build();
		var rpQoaConf = new QoaConfig(rpQoa, "rpId");
		Map<String, Integer> globalMapping = Map.of(
				"ClassA", 1,
				"ClassB", 2,
				"ClassC", 3
		);

		assertThat(QoaMappingUtil.validateCpContextClasses(
				comparison, contextClasses, cpQoaConf,
				requestClassRef, cpQoaConf,
				rpQoaConf, globalMapping, false),
				is(true)
		);

		assertThat(QoaMappingUtil.validateCpContextClasses(
				comparison, null, cpQoaConf,
				requestClassRef, cpQoaConf,
				rpQoaConf, Map.of(), false),
				is(true)
		);

		assertThat(QoaMappingUtil.validateCpContextClasses(
				comparison, Collections.emptyList(), cpQoaConf,
				requestClassRef, cpQoaConf,
				rpQoaConf, Map.of(), false),
				is(true)
		);

		assertThat(QoaMappingUtil.validateCpContextClasses(
				null, contextClasses, cpQoaConf,
				requestClassRef, cpQoaConf,
				rpQoaConf, Map.of(), false),
				is(true)
		);

		Map<String, Integer> emptyMapping = Collections.emptyMap();
		assertThrows(RequestDeniedException.class, () -> QoaMappingUtil.validateCpContextClasses(
				comparison, contextClasses, cpQoaConf,
				null, cpQoaConf,
				rpQoaConf, emptyMapping, false)
		);
		assertThat(QoaMappingUtil.validateCpContextClasses(
						comparison, contextClasses, rpQoaConf,
				null, cpQoaConf,
				rpQoaConf, emptyMapping, true),
				is(false)
		);

		assertThrows(RequestDeniedException.class, () -> QoaMappingUtil.validateCpContextClasses(
				comparison, contextClasses, cpQoaConf,
				"ClassC", cpQoaConf,
				rpQoaConf, globalMapping, false)
		);
		assertThat(QoaMappingUtil.validateCpContextClasses(
				comparison, contextClasses, cpQoaConf,
				"ClassC", cpQoaConf,
				rpQoaConf, globalMapping, true),
				is(false)
		);

		cpQoaConf.config().setEnforce(false);
		assertThrows(RequestDeniedException.class, () -> QoaMappingUtil.validateCpContextClasses(
				comparison, contextClasses, cpQoaConf,
				null, cpQoaConf,
				rpQoaConf, emptyMapping, false)
		);
		assertThat(QoaMappingUtil.validateCpContextClasses(
				comparison, contextClasses, cpQoaConf,
				null, cpQoaConf,
				rpQoaConf, emptyMapping, true),
				is(false)
		);

		cpQoaConf.config().setEnforce(false);
		rpQoaConf.config().setEnforce(false);
		assertThat(QoaMappingUtil.validateCpContextClasses(
				comparison, contextClasses, rpQoaConf,
				null, cpQoaConf,
				rpQoaConf, emptyMapping, false),
				is(false)
		);
	}

	private QualityOfAuthenticationConfig givenGlobalQoa() {
		Map<String, Integer> globalMapping = new HashMap<>();
		globalMapping.put(SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getName(),
				SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getLevel());
		globalMapping.put(SamlTestBase.Qoa.SOFTWARE_PKI.getName(),
				SamlTestBase.Qoa.SOFTWARE_PKI.getLevel());
		globalMapping.put(SamlTestBase.Qoa.KERBEROS.getName(),
				SamlTestBase.Qoa.KERBEROS.getLevel());
		globalMapping.put("ur:qoa:negative", -2);
		QualityOfAuthenticationConfig qoa = new QualityOfAuthenticationConfig();
		qoa.setMapping(globalMapping);
		qoa.setStrongestPossible("urn:qoa:strongest_possible");
		qoa.setDefaultQoa(SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getName());
		return qoa;
	}

	@Test
	void getQoaOrdersTest() {
		var classRef = "testClass1";
		var configOrder1 = 5;
		var acClass1 = AcClass.builder()
							 .order(configOrder1)
							 .contextClass(classRef)
							 .build();
		var configOrder2 = 10;
		var acClass2 = AcClass.builder()
							  .order(configOrder2)
							  .contextClass(classRef)
							  .build();
		var qoa = Qoa.builder()
					 .classes(List.of(acClass1, acClass2))
					 .enforce(true)
					 .build();
		var configQoa = new QoaConfig(qoa, "testId");
		Map<String, Integer> globalMapping = new HashMap<>();

		assertEquals(Set.of(configOrder1, configOrder2), QoaMappingUtil.getQoaOrders(classRef, configQoa, globalMapping, null));
		assertEquals(configOrder2, QoaMappingUtil.getMaxQoaOrder(List.of(classRef), configQoa, globalMapping));

		var mapOrder = 1;
		var mapClass = "testClass2";
		globalMapping.put(mapClass, mapOrder);
		assertEquals(Set.of(mapOrder), QoaMappingUtil.getQoaOrders(mapClass, configQoa, globalMapping, null));
		assertEquals(configOrder2, QoaMappingUtil.getMaxQoaOrder(List.of(classRef, mapClass), configQoa, globalMapping));

		var unknownClass = "unknownClass";
		assertThrows(TechnicalException.class, () ->
				QoaMappingUtil.getQoaOrders(unknownClass, configQoa, globalMapping, null)
		);
		List<String> unknownClasses = List.of(unknownClass);
		assertThrows(TechnicalException.class, () ->
				QoaMappingUtil.getMaxQoaOrder(unknownClasses, configQoa, globalMapping)
		);

		configQoa.config().setEnforce(false);
		assertDoesNotThrow(() ->
				QoaMappingUtil.getQoaOrders(unknownClass, configQoa, globalMapping, null)
		);
		assertDoesNotThrow(() ->
				QoaMappingUtil.getMaxQoaOrder(unknownClasses, configQoa, globalMapping)
		);

		var negativeClassRef = AcClass.builder()
				.order(-2)
				.contextClass(classRef)
				.build();
		var negativeQoa = Qoa.builder()
				.classes(List.of(negativeClassRef))
				.enforce(true)
				.build();
		var configNegativeQoa = new QoaConfig(negativeQoa, "testId");
		assertEquals(0, QoaMappingUtil.getMaxQoaOrder(List.of(classRef), configNegativeQoa, globalMapping));
	}

	@Test
	void computeQoasForComparisonTypeTest() {
		Map<String, Integer> globalMapping = givenGlobalQoa().getMapping();
		List<AcClass> acClasses = new ArrayList<>();
		acClasses.add(AcClass.builder().contextClass(SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getName()).build());
		acClasses.add(AcClass.builder().contextClass(SamlTestBase.Qoa.KERBEROS.getName()).build());
		var anyClass = "any";
		acClasses.add(AcClass.builder().contextClass(anyClass).build());
		var qoa = Qoa.builder().classes(acClasses).build();
		var qoaConfig = new QoaConfig(qoa, ISSUER);

		assertThat(QoaMappingUtil.computeQoasForComparisonType(new QoaConfig(null, ISSUER), globalMapping,
						Collections.emptyList()), is(empty()));

		qoa.setComparison(QoaComparison.EXACT);
		var exactQoa = QoaMappingUtil.computeQoasForComparisonType(qoaConfig, globalMapping, Collections.emptyList());
		assertThat(exactQoa, is(List.of(
				SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getName(),
				SamlTestBase.Qoa.KERBEROS.getName(),
				anyClass)));

		qoa.setComparison(QoaComparison.MINIMUM);
		var minQoa = QoaMappingUtil.computeQoasForComparisonType(qoaConfig, globalMapping, Collections.emptyList());
		assertThat(minQoa, is(List.of(SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getName())));

		qoa.setComparison(QoaComparison.MAXIMUM);
		var maxQoa = QoaMappingUtil.computeQoasForComparisonType(qoaConfig, globalMapping, Collections.emptyList());
		assertEquals(1, maxQoa.size());
		assertThat(maxQoa, is(List.of(SamlTestBase.Qoa.KERBEROS.getName())));
	}

	@Test
	void getMinQoaTest() {
		Map<String, Integer> globalMapping = givenGlobalQoa().getMapping();
		List<AcClass> acClasses = new ArrayList<>();

		acClasses.add(AcClass.builder().contextClass(SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getName()).build());
		List<String> minQQoa1 = QoaMappingUtil.getMinQoa(acClasses, Collections.emptyList(), ISSUER, globalMapping);
		assertEquals(1, minQQoa1.size());
		assertEquals(SamlContextClass.MOBILE_ONE_FACTOR_UNREGISTERED, minQQoa1.get(0));

		acClasses.add(AcClass.builder().contextClass(SamlTestBase.Qoa.KERBEROS.getName()).build());
		List<String> minQoa2 = QoaMappingUtil.getMinQoa(acClasses, Collections.emptyList(), ISSUER, globalMapping);
		assertEquals(1, minQoa2.size());
		assertEquals(SamlContextClass.MOBILE_ONE_FACTOR_UNREGISTERED, minQoa2.get(0));

		acClasses.add(AcClass.builder().contextClass("any").build());
		List<String> minQoa3 = QoaMappingUtil.getMinQoa(acClasses, Collections.emptyList(), ISSUER, globalMapping);
		assertEquals(1, minQoa3.size());
		assertEquals(SamlContextClass.MOBILE_ONE_FACTOR_UNREGISTERED, minQoa3.get(0));

		acClasses.add(AcClass.builder().contextClass("ur:qoa:negative").build());
		List<String> minQQoa4 = QoaMappingUtil.getMinQoa(acClasses, Collections.emptyList(), ISSUER, globalMapping);
		assertEquals(1, minQQoa4.size());
		assertEquals(SamlContextClass.MOBILE_ONE_FACTOR_UNREGISTERED, minQQoa4.get(0));
	}


	@Test
	void getMaxQoaTest() {
		Map<String, Integer> globalMapping = givenGlobalQoa().getMapping();
		List<AcClass> acClasses = new ArrayList<>();

		acClasses.add(AcClass.builder().contextClass(SamlTestBase.Qoa.MOBILE_ONE_FACTOR_UNREGISTERED.getName()).build());
		List<String> maxQoa1 = QoaMappingUtil.getMaxQoa(acClasses, Collections.emptyList(), ISSUER, globalMapping);
		assertEquals(1, maxQoa1.size());
		assertEquals(SamlContextClass.MOBILE_ONE_FACTOR_UNREGISTERED, maxQoa1.get(0));

		acClasses.add(AcClass.builder().contextClass(SamlTestBase.Qoa.KERBEROS.getName()).build());
		List<String> maxQoa2 = QoaMappingUtil.getMaxQoa(acClasses, Collections.emptyList(), ISSUER, globalMapping);
		assertEquals(1, maxQoa2.size());
		assertEquals(SamlContextClass.KERBEROS, maxQoa2.get(0));

		acClasses.add(AcClass.builder().contextClass("any").build());
		List<String> maxQoa3 = QoaMappingUtil.getMaxQoa(acClasses, Collections.emptyList(), ISSUER, globalMapping);
		assertEquals(1, maxQoa3.size());
		assertEquals(SamlContextClass.KERBEROS, maxQoa3.get(0));

		acClasses.add(AcClass.builder().contextClass("ur:qoa:negative").build());
		List<String> maxQoa4 = QoaMappingUtil.getMaxQoa(acClasses, Collections.emptyList(), ISSUER, globalMapping);
		assertEquals(1, maxQoa4.size());
		assertEquals(SamlContextClass.KERBEROS, maxQoa4.get(0));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null, 10, -1, 10",
			"class40, 40, -1, 40",
			"null, null, -1, -1",
			"any, null, -1, -1",
			"any, null, 999, 999",
			"urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorUnregistered, null, -1, 10",
	}, nullValues = "null")
	void getAcClassOrderTest(String contextClass, Integer acClassOrder, Integer undefinedOrder, Integer result) {
		Map<String, Integer> globalMapping = givenGlobalQoa().getMapping();
		var acClass = AcClass.builder()
							 .contextClass(contextClass)
							 .order(acClassOrder)
							 .build();
		assertEquals(result, QoaMappingUtil.getAcClassOrder(acClass, ISSUER, globalMapping, undefinedOrder));
	}
}
