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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.federation.xmlconfig.AcClass;
import swiss.trustbroker.federation.xmlconfig.Qoa;
import swiss.trustbroker.federation.xmlconfig.QoaComparison;
import swiss.trustbroker.mapping.dto.CustomQoa;
import swiss.trustbroker.mapping.dto.QoaConfig;

/**
 * Mostly internal helper for QoaMappingService.
 * Otherwise, to be used from static contexts only.
 */
@Slf4j
public class QoaMappingUtil {

	private QoaMappingUtil() {
	}

	/**
	 * @param requestQoaConf config corresponding to expectedContextClasses
	 * @param cpQoaConf config corresponding to actualContextClass
	 * @param rpQoaConf config for RP - only used for enforcement check
	 */
	@SuppressWarnings("java:S107") // large number of parameters as it's used from static context
	public static boolean validateCpContextClasses(
			QoaComparison comparison, List<String> expectedContextClasses, QoaConfig requestQoaConf, // request
			String actualContextClass, QoaConfig cpQoaConf, // response
			QoaConfig rpQoaConf, Map<String, Integer> globalMapping, boolean checkOnly) {

		if (CollectionUtils.isEmpty(expectedContextClasses)) {
			log.debug("Missing State expectedCtxClasses cpIssuer={}, skipping AuthnContextClassRef validation", cpQoaConf.issuerId());
			return true;
		}

		if (comparison == null) {
			log.debug("Missing Qoa comparison cpIssuer={}, skipping AuthnContextClassRef validation", cpQoaConf.issuerId());
			return true;
		}

		if (!StringUtils.hasLength(actualContextClass)) {
			if (!checkOnly) {
				missingQoaException(comparison, expectedContextClasses, cpQoaConf, rpQoaConf);
			}
			return false;
		}

		Set<Integer> qoaOrders = getQoaOrders(actualContextClass, cpQoaConf, globalMapping, false);
		Set<Integer> contextClassOrders = expectedContextClasses.stream()
				.flatMap(acClass -> getQoaOrders(acClass, requestQoaConf, globalMapping, false).stream())
				.collect(Collectors.toSet());

		var isValid = validateQoaComparison(cpQoaConf, comparison, contextClassOrders, qoaOrders);
		if (!isValid && !checkOnly) {
			invalidQoaException(comparison, actualContextClass, expectedContextClasses, cpQoaConf, rpQoaConf);
		}
		return isValid;
	}

	static boolean validateQoaComparison(QoaConfig cpQoaConf, QoaComparison comparison, Set<Integer> expectedQoaOrders,
			Set<Integer> actualQoas) {

		if (CollectionUtils.isEmpty(expectedQoaOrders)) {
			log.debug("Missing Qoa orders cpIssuer={}, skipping comparison validation", cpQoaConf.issuerId());
			return true;
		}

		var qoaMin = Collections.min(expectedQoaOrders);
		var qoaMax = Collections.max(expectedQoaOrders);

		return (comparison != null) && switch (comparison) {
			// the resulting authentication context in the authentication statement MUST be the exact match of
			// at least one of the authentication contexts specified.
			case EXACT -> expectedQoaOrders.stream().anyMatch(actualQoas::contains);
			// the resulting authentication context in the authentication statement MUST be at least as
			// strong (as deemed by the responder) as one of the authentication contexts specified.
			case MINIMUM -> actualQoas.stream().anyMatch(actualQoa -> actualQoa >= qoaMin);
			//  the resulting authentication context in the authentication statement MUST be as strong as possible
			//  (as deemed by the responder) without exceeding the strength of at least one of the authentication contexts specified.
			case MAXIMUM -> actualQoas.stream().anyMatch(actualQoa -> actualQoa <= qoaMax && actualQoa >= qoaMin);
			// the resulting authentication context in the authentication statement MUST be stronger (as deemed by the responder)
			// than any one of the authentication contexts specified.
			case BETTER -> actualQoas.stream().anyMatch(actualQoa -> actualQoa > qoaMin);
		};
	}

	private static void invalidQoaException(QoaComparison comparison, String actualContextClass,
			List<String> expectedContextClasses, QoaConfig cpQoaConf, QoaConfig rpQoaConf) {
		invalidQoaException(comparison, List.of(actualContextClass), expectedContextClasses, cpQoaConf, rpQoaConf);
	}

	static void invalidQoaException(QoaComparison comparison, List<String> actualContextClasses,
			List<String> expectedContextClasses, QoaConfig cpQoaConf, QoaConfig rpQoaConf) {
		if (!cpQoaConf.hasConfig() && !rpQoaConf.hasConfig()) {
			return;
		}
		if (enforceQoa(rpQoaConf, cpQoaConf)) {
			throw new RequestDeniedException(
					String.format("Invalid Qoa in request actualCtxClasses=%s cpIssuer=%s expectedCtxClasses=%s comparison=%s "
									+ "rpIssuer=%s",
							actualContextClasses, cpQoaConf.issuerId(), expectedContextClasses, comparison, rpQoaConf.issuerId()));
		}
		else {
			log.warn("Qoa.enforce=false. Invalid Qoa in request actualCtxClasses=\"{}\" cpIssuer=\"{}\" "
							+ "expectedCtxClasses=\"{}\" comparison=\"{}\" rpIssuer=\"{}\"",
					actualContextClasses, cpQoaConf.issuerId(), expectedContextClasses, comparison, rpQoaConf.issuerId());
		}
	}

	public static boolean enforceQoa(QoaConfig rpQoaConf, QoaConfig cpQoaConf) {
		var cpEnforce = cpQoaConf.hasConfig() && cpQoaConf.config().isEnforce();
		var rpEnforce = rpQoaConf.hasConfig() && rpQoaConf.config().isEnforce();
		return cpEnforce || rpEnforce;
	}

	public static void validateRpContextClasses(QoaConfig configQoa, List<String> requestContextClasses,
			AuthnContextComparisonTypeEnumeration comparison, Map<String, Integer> globalMapping) {

		log.debug("Incoming requestCtxClasses={}, issuer={}", requestContextClasses, configQoa.issuerId());

		if (!configQoa.hasConfig()) {
			log.debug("Missing Qoa config for issuer={} - skipping Qoa validation", configQoa.issuerId());
			return;
		}

		if (comparison == null) {
			log.debug("Missing Qoa Comparison issuer={}", configQoa.issuerId());
		}

		isKnownQoaLevels(requestContextClasses, configQoa, globalMapping, false);
	}

	static void isKnownQoaLevels(List<String> requestContextClasses, QoaConfig configQoa, Map<String, Integer> globalMapping,
			Boolean outbound) {

		for (var contextClass : requestContextClasses) {

			// check if the QOA level is known in Rp or Global config
			var orders = getQoaOrders(contextClass, configQoa, globalMapping, outbound);

			// check config class to determine level
			var configAcClasses = getConfigAcClasses(contextClass, configQoa.config(), outbound);
			// 	Accept QOA with different name but same order
			if (!orders.isEmpty() && configAcClasses .isEmpty()) {
				configAcClasses = getConfigAcClassesByOrders(configQoa, orders, globalMapping, outbound);
			}
			if (configAcClasses.isEmpty() || orders.isEmpty()) {
				invalidQoaException(configQoa, contextClass);
			}
		}
	}

	public static List<AcClass> getConfigAcClassesByOrders(QoaConfig configQoa, Set<Integer> orders,
			Map<String, Integer> globalMapping, Boolean outbound) {
		List<AcClass> result = new ArrayList<>();
		if (orders.isEmpty() || !configQoa.hasConfig()) {
			return result;
		}
		for (var acClass : configQoa.config().getClasses()) {
			if (acClass.applyForDirection(outbound)) {
				var configQoaOrder =
						getAcClassOrder(acClass, configQoa.issuerId(), globalMapping, CustomQoa.UNDEFINED_QOA_ORDER);
				if (orders.contains(configQoaOrder)) {
					result.add(acClass);
				}
			}
			// else: ACClass for one direction only, ignore for the other
		}
		return result;
	}

	private static void invalidQoaException(QoaConfig configQoa, String contextClass) {
		if (!configQoa.hasConfig()) {
			log.debug("Missing qoa configuration for={}, disabled Qoa validation of issuer={}",
					configQoa.issuerId(), contextClass);
			return;
		}
		if (configQoa.config().isEnforce()) {
			throw new TechnicalException(
					String.format("Missing ctxClass=%s in config (HINT: check application.yaml trustbroker.config.qoa"
							+ " or the SetupRP.xml) for rpIssuer=%s qoaConf=%s", contextClass, configQoa.issuerId(), configQoa));
		}
		else {
			log.warn("Qoa.enforce=false. Missing ctxClass=\"{}\" in config  (HINT: check application.yaml trustbroker.config.qoa"
					+ " or the SetupRP.xml) for rpIssuer=\"{}\" qoaConf=\"{}\"", contextClass, configQoa.issuerId(), configQoa);
		}
	}

	public static void missingQoaException(QoaComparison comparison, List<String> expectedContextClasses,
			QoaConfig cpQoaConf, QoaConfig rpQoaConf) {

		if (!cpQoaConf.hasConfig() && !rpQoaConf.hasConfig()) {
			return;
		}

		var cpEnforce = cpQoaConf.hasConfig() && cpQoaConf.config().isEnforce();
		var rpEnforce = rpQoaConf.hasConfig() && rpQoaConf.config().isEnforce();

		if (cpEnforce || rpEnforce) {
			throw new RequestDeniedException(String.format("Missing Qoa in request cpIssuer=%s, expectedCtxClasses=%s "
					+ "comparison=%s rpIssuer=%S", cpQoaConf.issuerId(), expectedContextClasses, comparison, rpQoaConf.issuerId()));
		}
		else {
			log.warn("Qoa.enforce=false. Missing Qoa in request cpIssuer=\"{}\" expectedContextClasses=\"{}\" comparison=\"{}\" "
					+ "rpIssuer=\"{}\"", cpQoaConf.issuerId(), expectedContextClasses, comparison, rpQoaConf.issuerId());
		}
	}

	static List<AcClass> getConfigAcClasses(String contextClass, Qoa configQoa, Boolean outbound) {
		if (configQoa == null || CollectionUtils.isEmpty(configQoa.getClasses())) {
			return Collections.emptyList();
		}
		List<AcClass> result = new ArrayList<>();
		for (var acClass : configQoa.getClasses()) {
			if (acClass.applyForDirection(outbound) && Objects.equals(acClass.getContextClass(), contextClass)) {
				result.add(acClass);
			}
		}
		return result;
	}

	public static List<String> getQoasByLevels(Set<Integer> levels, Map<String, Integer> globalMapping) {
		List<String> result = new ArrayList<>();
		for (Map.Entry<String, Integer> entry : globalMapping.entrySet()) {
			if (levels.contains(entry.getValue())) {
				result.add(entry.getKey());
			}
		}
		return result;
	}

	public static Integer getMaxQoaOrder(List<String> classRefs, QoaConfig configQoa, Map<String, Integer> globalMapping) {
		if (CollectionUtils.isEmpty(classRefs)) {
			return CustomQoa.UNDEFINED_QOA_ORDER;
		}
		// usually
		var maxQoa = classRefs.stream()
				.flatMap(contextClass -> getQoaOrders(contextClass, configQoa, globalMapping, null).stream())
				.max(Integer::compareTo)
				.orElse(0);
		log.debug("issuer={} returned contextClasses={} with max qoa={}", configQoa.issuerId(), classRefs, maxQoa);
		return maxQoa;
	}

	public static Set<Integer> getQoaOrders(String classRef, QoaConfig configQoa, Map<String, Integer> globalMapping,
			Boolean outbound) {
		var configAcClasses = getConfigAcClasses(classRef, configQoa.config(), outbound);
		if (!configAcClasses.isEmpty()) {
			var result = configAcClasses.stream()
				.map(AcClass::getOrder)
				.filter(Objects::nonNull)
				.collect(Collectors.toSet());
			if (!result.isEmpty()) {
				return result;
			}
		}
		var level = globalMapping.get(classRef);
		if (level == null) {
			if (!configQoa.hasConfig()) {
				return Set.of(CustomQoa.UNDEFINED_QOA_ORDER);
			}
			if (configQoa.config().isEnforce()) {
				// level must be defined in Global or RP config, otherwise SSO will not work
				throw new TechnicalException(String.format("Missing Qoa in config ctxClass=%s issuer=%s, cannot determine order"
						+ "(HINT: check trustbroker.config.qoa or the SetupRP.xml/SetupCP.xml)",
						classRef, configQoa.issuerId()));
			}
			else {
				log.warn("Qoa.enforce=false. Missing Qoa in config ctxClass=\"{}\" issuer=\"{}\", cannot determine "
						+ "order (HINT: check trustbroker.config.qoa or the SetupRP.xml/SetupCP.xml)",
						classRef, configQoa.issuerId());
			}
			return Set.of(CustomQoa.UNDEFINED_QOA_ORDER);
		}
		return Set.of(level);
	}

	public static List<String> computeQoasForComparisonType(QoaConfig configQoa, Map<String, Integer> globalMapping,
			List<String> matchContextClasses) {
		if (!configQoa.hasConfig()) {
			return Collections.emptyList();
		}
		var comparison = configQoa.config().getComparison();
		var contextClasses = configQoa.config().getClasses();
		if (comparison == null) {
			comparison = QoaComparison.EXACT;
		}
		return switch (comparison) {
			case EXACT -> getExactQoas(contextClasses, matchContextClasses);
			case MINIMUM, BETTER -> getMinQoa(contextClasses, matchContextClasses, configQoa.issuerId(), globalMapping);
			case MAXIMUM -> getMaxQoa(contextClasses, matchContextClasses, configQoa.issuerId(), globalMapping);
		};
	}

	static List<String> getExactQoas(List<AcClass> contextClasses, List<String> matchContextClasses) {
		return contextClasses.stream()
				.filter(contextClass -> matchContextClass(contextClass, matchContextClasses))
					.map(AcClass::getContextClass)
					.filter(Objects::nonNull)
					.distinct()
					.toList();
	}

	static List<String> getMinQoa(List<AcClass> classes, List<String> matchContextClasses, String issuerId,
			Map<String, Integer> globalMapping) {
		var minQOa = classes.stream()
				.filter(acClass -> matchContextClass(acClass, matchContextClasses))
				.min(
						(acClass1, acClass2) -> compare(acClass1, acClass2, issuerId, globalMapping, Integer.MAX_VALUE));
		return getContextClassList(minQOa);
	}

	static List<String> getMaxQoa(List<AcClass> classes, List<String> matchContextClasses, String issuerId,
			Map<String, Integer> globalMapping) {
		var maxQoa = classes.stream()
				.filter(acClass -> matchContextClass(acClass, matchContextClasses))
				.max(
				(acClass1, acClass2) -> compare(acClass1, acClass2, issuerId, globalMapping, Integer.MIN_VALUE));
		return getContextClassList(maxQoa);
	}

	private static List<String> getContextClassList(Optional<AcClass> qoa) {
		if (qoa.isEmpty()) {
			return Collections.emptyList();
		}
		return List.of(qoa.get().getContextClass());
	}

	private static boolean matchContextClass(AcClass contextClass, List<String> matchContextClasses) {
		if (matchContextClasses.isEmpty()) {
			return true;
		}
		return matchContextClasses.contains(contextClass.getContextClass());
	}

	private static int compare(AcClass acClass1, AcClass acClass2,
			String issuerId, Map<String, Integer> globalMapping, Integer undefinedOrder) {
		var order1 = getAcClassOrder(acClass1, issuerId, globalMapping, undefinedOrder);
		var order2 = getAcClassOrder(acClass2, issuerId, globalMapping, undefinedOrder);
		return order1.compareTo(order2);
	}

	static Integer getAcClassOrder(AcClass acClass, String issuerId, Map<String, Integer> globalMapping, Integer undefinedOrder) {
		var order = acClass.getOrder();
		if (order == null) {
			order = globalMapping.get(acClass.getContextClass());
		}
		if (order == null || order == CustomQoa.UNDEFINED_QOA_ORDER) {
			order = undefinedOrder;
			log.info("Could not determine Qoa level for issuerId={} contextClass={} using={}",
					issuerId, acClass.getContextClass(), order);
		}
		return order;
	}
}
