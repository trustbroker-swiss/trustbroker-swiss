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

package swiss.trustbroker.util;

import java.util.ArrayList;
import java.util.List;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import swiss.trustbroker.api.homerealmdiscovery.attributes.HrdClaimsProviderToRelyingPartyMapping;
import swiss.trustbroker.api.homerealmdiscovery.attributes.HrdHttpData;
import swiss.trustbroker.api.homerealmdiscovery.service.HrdService;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderRelyingParty;
import swiss.trustbroker.oidc.session.HttpExchangeSupport;

/**
 * Log-able web input (where we do not expected any <i>StringUtil.clean</i> modified data) and other helpers.
 */
@Slf4j
public class HrdSupport {

	public static final String HTTP_URLTESTER_CP = "urltester"; // sent by system teams URL-Tester to skip HRD

	public static final String HTTP_CP_HINT = "idp";

	private HrdSupport() {
	}

	private static String getClaimsProviderWithPepIdpHint(String hint, TrustBrokerProperties properties) {
		hint = hint.toUpperCase().replace("LOGIN", "-LOGIN");
		if (properties.getEnterpriseIdpId().endsWith(hint)) {
			return properties.getEnterpriseIdpId();
		}
		else if (properties.getPublicIdpId().endsWith(hint)) {
			return properties.getPublicIdpId();
		}
		else if (properties.getMobileIdpId().endsWith(hint)) {
			return properties.getMobileIdpId();
		}
		return null;
	}

	public static boolean requestFromTestApplication(HttpServletRequest request) {
		return WebUtil.getCookie(HTTP_URLTESTER_CP, request) != null
				|| WebUtil.getHeader(HTTP_URLTESTER_CP, request) != null;
	}

	private static boolean hasAutoLoginDisabled(HttpServletRequest request, TrustBrokerProperties properties) {
		var autLoginCookie = properties.getPublicAutoLoginCookie();
		if (StringUtils.isNotEmpty(autLoginCookie)) {
			var cookieValue = WebUtil.getCookie(autLoginCookie, request);
			return "FALSE".equalsIgnoreCase(cookieValue); // true disables all HRD CP filtering
		}
		return false;
	}


	// Claims provider hints are used to do autoLogin routing to a preferred IDP without displaying an HRD screen
	public static String getClaimsProviderHint(HttpServletRequest request, TrustBrokerProperties properties) {
		var reason = "default";
		if (request == null) {
			return null;
		}

		// Testing hint: HTTP urltester header signaling selected CP independent of network etc. required for automation
		var cpSelection = WebUtil.getCookie(HTTP_URLTESTER_CP, request);
		reason = updateReason(cpSelection, HTTP_URLTESTER_CP + " cookie", reason);
		if (cpSelection == null) {
			cpSelection = WebUtil.getHeader(HTTP_URLTESTER_CP, request);
			reason = updateReason(cpSelection, HTTP_URLTESTER_CP + " header", reason);
		}

		// CP (IDP) hint: idp=xyz is supported there as a REST hint by applications
		if (cpSelection == null && WebUtil.getParameter(HTTP_CP_HINT, request) != null) {
			var hint = StringUtil.clean(WebUtil.getParameter(HTTP_CP_HINT, request));
			cpSelection = getClaimsProviderWithPepIdpHint(hint, properties);
			reason = updateReason(cpSelection, HTTP_CP_HINT + " param", reason);
		}

		// Testing hint: HTTP autoLogin cookie Disabling autoLogin behavior so testers can select CP manually
		if (cpSelection == null && hasAutoLoginDisabled(request, properties)) {
			log.debug("HRD detected {}=FALSE cookie signaling tester to select CP manually",
					properties.getPublicAutoLoginCookie());
			return null;
		}

		// Mobile hint: Using mobile GW/CP requires direct dispatching except when we already bailed out autoLogin=FALSE
		// In this case the mobile CP is displayed for testing purposes even though login is not possible.
		if (cpSelection == null && properties.getNetwork() != null &&
				StringUtils.isNotEmpty(properties.getNetwork().getMobileGatewayIpRegex())) {
			var clientIps = WebSupport.getGatewayIps(request);
			var gatewayIp = properties.getNetwork().getMobileGatewayIpRegex();
			if (isGateWayIp(clientIps, gatewayIp)) {
				cpSelection = properties.getMobileIdpId();
				reason = updateReason(cpSelection, "gatewayIPAddress=" + gatewayIp, reason);
			}
		}

		log.debug("HRD routing step 1 lead to cpSelection={} with reason={}", cpSelection, reason);
		return cpSelection;
	}

	private static boolean isGateWayIp(String[] clientIps, String gatewayIp) {
		for (var clientIp : clientIps) {
			if (clientIp.matches(gatewayIp)) {
				return true;
			}
		}
		return false;
	}

	private static String updateReason(String cpSelection, String override, String reason) {
		return cpSelection != null ? override : reason;
	}

	// OIDC routing variant when we have 3 copy&pasted SetupRP files not consolidated into a single one
	// Deprecate/discard this code as soon as all Oidc.Client are not distributed over multiple files anymore.
	public static String getClaimsProviderHint(TrustBrokerProperties properties) {
		var request = HttpExchangeSupport.getRunningHttpRequest();
		if (request == null) {
			return null;
		}
		var cpSelection = getClaimsProviderHint(request, properties);
		if (cpSelection == null && WebSupport.getClientNetwork(request, properties.getNetwork()) != null) {
			if (WebSupport.isIntranet(request, properties.getNetwork())) {
				cpSelection = properties.getEnterpriseIdpId();
			}
			else if (WebSupport.isClientOnInternet(request, properties.getNetwork())) {
				cpSelection = properties.getPublicIdpId();
			}
		}
		log.debug("HRD routing OIDC pre-selection lead to cpSelection={}", cpSelection);
		return cpSelection;
	}

	public static List<ClaimsProviderRelyingParty> reduceClaimsProviderMappings(
			HttpServletRequest request, String rpIssuer, String applicationName,
			String cpSelectionHint, List<ClaimsProviderRelyingParty> cpMappings,
			TrustBrokerProperties trustBrokerProperties,
			HrdService hrdService) {

		// bailout if we have only a single CP based on config or groovy scripting
		if (cpMappings  == null || cpMappings.size() < 2) {
			return cpMappings;
		}

		// matching hint first as it should select an existing CP and we are done including the mobile GW
		cpMappings = filterMappingsForHint(cpSelectionHint, cpMappings);

		// throw out all CPs not valid for current network (not applied if cpSelectionHint already chose aa single CP)
		cpMappings = filterMappingsForNetwork(request, cpMappings, trustBrokerProperties);

		// if autoLogin=FALSE cookie is present we keep all CPs for selection except if not allowed on the network before
		if (hasAutoLoginDisabled(request, trustBrokerProperties)) {
			return filterMappingDuplicates(cpMappings);
		}

		// pick an exact match of the alias using applName or OIDC client_id first, then SAML issuerID
		cpMappings = filterMappingsForRelyingPartyAlias(applicationName, cpMappings); // OIDC client_id
		cpMappings = filterMappingsForRelyingPartyAlias(rpIssuer, cpMappings); // SAML Issuer ID

		cpMappings = mapResultMappings(hrdService.adaptClaimsProviderMappings(HrdHttpData.of(request), cpMappings));

		// discard all remaining mappings with a relyingPartyAlias except if we only have such still
		cpMappings = filterMappingsForNonMatchingAliases(cpMappings);

		return cpMappings;
	}

	// map elements if they are not ClaimsProviderRelyingParty
	private static List<ClaimsProviderRelyingParty> mapResultMappings(List<HrdClaimsProviderToRelyingPartyMapping> mappings) {
		List<ClaimsProviderRelyingParty> result = new ArrayList<>(mappings.size());
		for (var mapping : mappings) {
			result.add(ClaimsProviderRelyingParty.of(mapping));
		}
		return result;
	}

	private static List<ClaimsProviderRelyingParty> filterMappingDuplicates(List<ClaimsProviderRelyingParty> cpMappings) {
		var dup = new ArrayList<String>();
		var ret = new ArrayList<ClaimsProviderRelyingParty>();
		cpMappings.forEach(m -> {
			if (!dup.contains(m.getId())) {
				dup.add(m.getId());
				ret.add(m);

			}
		});
		return ret;
	}

	private static List<ClaimsProviderRelyingParty> filterMappingsForHint(String cpSelectionHint,
			List<ClaimsProviderRelyingParty> cpMappings) {
		if (cpMappings.size() < 2 || cpSelectionHint == null) {
			return cpMappings;
		}
		var selectedCp = cpMappings.stream().filter(cpm -> cpm.getId().equals(cpSelectionHint)).toList();
		log.debug("Got idpHint={} reducing CP mappings from {} to 1 entry", cpSelectionHint, cpMappings.size());
		if (!selectedCp.isEmpty()) {
			var newList = new ArrayList<ClaimsProviderRelyingParty>(); // eliminate output duplicates
			newList.add(selectedCp.get(0));
			return newList;
		}
		return cpMappings;
	}

	private static List<ClaimsProviderRelyingParty> filterMappingsForNetwork(HttpServletRequest request,
			List<ClaimsProviderRelyingParty> cpMappings, TrustBrokerProperties properties) {
		if (cpMappings.size() < 2) {
			return cpMappings;
		}
		var network = WebSupport.getClientNetworkOnIntranet(request, properties.getNetwork());
		if (network == null) {
			return cpMappings;
		}
		var newList = new ArrayList<>(cpMappings.stream().filter(cpm -> cpm.isValidForNetwork(network)).toList());
		if (log.isDebugEnabled()) {
			var networkHeader = properties.getNetwork() != null ? properties.getNetwork().getNetworkHeader() : null;
			log.debug("Got {}={} reducing CP mappings from {} to {} entries", networkHeader, network,
					cpMappings.size(), newList.size());
		}
		return newList.isEmpty() ? cpMappings : newList;
	}

	private static List<ClaimsProviderRelyingParty> filterMappingsForRelyingPartyAlias(String rpOrAppId,
			List<ClaimsProviderRelyingParty> cpMappings) {
		if (cpMappings.size() < 2 || rpOrAppId == null) {
			return cpMappings;
		}
		var newList = new ArrayList<>(cpMappings.stream().filter(cpm -> cpm.isMatchingRelyingPartyAlias(rpOrAppId)).toList());
		log.debug("Got relyingPartyAlias={} reducing CP mappings from {} to {} entries", rpOrAppId,
				cpMappings.size(), newList.size());
		return newList.isEmpty() ? cpMappings : newList;
	}

	private static List<ClaimsProviderRelyingParty> filterMappingsForNonMatchingAliases(
			List<ClaimsProviderRelyingParty> cpMappings) {
		if (cpMappings.size() < 2) {
			return cpMappings;
		}
		var newList = new ArrayList<>(cpMappings.stream().filter(cpm -> cpm.getRelyingPartyAlias() == null).toList());
		log.debug("Discard relyingPartyAlias entries reducing CP mappings from {} to {} entries",
				cpMappings.size(), newList.size());
		return newList.isEmpty() ? cpMappings : newList;
	}

}
