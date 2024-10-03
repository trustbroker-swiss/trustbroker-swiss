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

import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.net.URLBuilder;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.view.UrlBasedViewResolver;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.tracing.TraceSupport;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.dto.NetworkConfig;

/**
 * Log-able web input (where we do not expected any StringUtil. clean modified data) and other helpers.
 */
@Slf4j
public class WebSupport {

	public static final String HTTP_HEADER_X_REAL_IP = WebUtil.HTTP_HEADER_X_REAL_IP;

	public static final String HTTP_HEADER_DEVICE_ID = "X-DevId"; // our device fingerprinting

	public static final String HTTP_HEADER_XTB_PROFILE_ID = "XTB-ProfileId";

	public static final String XTB_ALTERNATE_METADATA_ENDPOINT = "/FederationMetadata/2007-06/FederationMetadata.xml";

	public static final String LOWER_CASE_METADATA_ENDPOINT = "/federationmetadata/2007-06/federationmetadata.xml";

	public static final String ADFS_ENTRY_URL = "/adfs/ls";

	public static final String ADFS_ENTRY_URL_TRAILING_SLASH = ADFS_ENTRY_URL + "/";

	public static final String XTB_LEGACY_ENTRY_URL = "trustbroker/adfs/ls"; // deprecated

	public static final String USERNAME = "username";

	public static final String HTTP_REMOTE_USER = WebUtil.HTTP_REMOTE_USER;

	public static final String ADMINLOGIN = "adminlogin";

	public static final int COOKIE_MAXAGE_SESSION = -1;

	private WebSupport() {
	}

	public static String getDeviceId(HttpServletRequest request) {
		return WebUtil.getHeader(HTTP_HEADER_DEVICE_ID, request);
	}

	public static HttpServletRequest getWebRequest() {
		// we are within spring so a spring-mvc filter provides us with this information
		var attrs = RequestContextHolder.getRequestAttributes();
		return attrs != null ? ((ServletRequestAttributes) attrs).getRequest() : null;
	}

	public static String getClientNetwork(HttpServletRequest request, NetworkConfig networkConfig) {
		return networkConfig != null ? WebUtil.getHeader(networkConfig.getNetworkHeader(), request) : null;
	}

	// On INTRANET allow testing HRD with X-Simulated-Client-Network header
	public static String getClientNetworkOnIntranet(HttpServletRequest request, NetworkConfig networkConfig) {
		var network = getClientNetwork(request, networkConfig);
		if (networkConfig != null && networkConfig.isIntranet(network)) {
			var simulatedNetwork = WebUtil.getHeader(networkConfig.getTestNetworkHeader(), request);
			network = simulatedNetwork != null ? simulatedNetwork : network;
		}
		return network;
	}

	public static String getUserAgent(HttpServletRequest request) {
		return WebUtil.getUserAgent(request);
	}

	public static boolean isIntranet(HttpServletRequest request, NetworkConfig networkConfig) {
		return networkConfig != null && networkConfig.isIntranet(getClientNetwork(request, networkConfig));
	}

	public static boolean isAdminLogin(HttpServletRequest request) {
		return WebUtil.getParameter(ADMINLOGIN, request) != null;
	}

	public static boolean isLbHealthCheck(HttpServletRequest request, NetworkConfig networkConfig) {
		return "/actuator/health".equals(request.getRequestURI())
				&& isIntranet(request, networkConfig)
				&& WebUtil.getHeader(HTTP_HEADER_X_REAL_IP, request) != null;
	}

	// Internal access: header is null (K8S, LB probe, development)
	// LB sends value otherwise
	public static boolean isClientOnInternet(HttpServletRequest request, NetworkConfig networkConfig) {
		return networkConfig != null && networkConfig.isInternet(getClientNetwork(request, networkConfig));
	}

	// append to exceptions to correlate clients with have problems with
	// NOTE that clientIp and traceId are now also set in the console log via logging.pattern (see application.yml)
	public static String getClientHint(HttpServletRequest request, NetworkConfig networkConfig) {
		// not called from web
		if (request == null) {
			return "client='NONE'";
		}

		// LB forwarded client IP
		var sb = new StringBuilder();
		var clientNetwork = getClientNetwork(request, networkConfig);
		if (clientNetwork != null) {
			sb.append("clientNetwork='");
			sb.append(clientNetwork);
			sb.append("' ");
		}
		// LB forwarded client IP
		var ip = WebUtil.getClientIp(request);
		if (ip != null) {
			sb.append("clientIP='");
			sb.append(ip);
			sb.append("' ");
		}
		// Our own traceId, but maybe we have a proxy injecting us a X-B3-TraceId header
		var traceId = TraceSupport.getOwnTraceParent();
		if (traceId != null) {
			sb.append("traceId='");
			sb.append(traceId);
			sb.append("' ");
		}
		// user agent
		var userAgent = getUserAgent(request);
		if (userAgent != null) {
			sb.append("userAgent='");
			sb.append(userAgent);
			sb.append("' ");
		}
		var deviceId = WebUtil.getHeader(HTTP_HEADER_DEVICE_ID, request);
		if (deviceId != null) {
			if (userAgent != null) {
				// discard duplicated User-Agent in X-DevId
				deviceId = deviceId.replace(deviceId, "...");
			}
			sb.append("deviceId='");
			sb.append(deviceId);
			sb.append("' ");
		}
		// referrer
		var referrer = WebUtil.getHeader(HttpHeaders.REFERER, request);
		if (referrer != null) {
			sb.append("referrer='");
			sb.append(referrer);
			sb.append("' ");
		}
		return StringUtil.clean(sb.toString(), " ");
	}

	public static String getServiceContext(HttpServletRequest request) {
		return WebUtil.getServiceContext(request);
	}

	// throws an exception if the parameter is present more than once
	public static String getUniqueQueryParameter(URLBuilder urlBuilder, String name) {
		var queryParams = urlBuilder.getQueryParams();
		var params = queryParams.stream()
				.filter(pair -> name.equals(pair.getFirst()))
				.toList();
		if (params.isEmpty()) {
			return null;
		}
		if (params.size() > 1) {
			// should not happen in a proper requests, might be an attack
			throw new RequestDeniedException(String.format("Query parameter %s occurs more than once", name));
		}
		return params.get(0).getSecond();
	}

	public static String getViewRedirectResponse(String url) {
		if (url == null) {
			return null;
		}
		return UrlBasedViewResolver.REDIRECT_URL_PREFIX + url;
	}

	public static boolean isFederationMetaRequest(HttpServletRequest request) {
		// some peers are case-insensitive and clients might have had miss-configuration
		return HttpMethod.GET.matches(request.getMethod()) &&
				WebSupport.XTB_ALTERNATE_METADATA_ENDPOINT.equalsIgnoreCase(request.getRequestURI());
	}

	public static boolean isSupportedFederationMeta(String path) {
		return WebSupport.XTB_ALTERNATE_METADATA_ENDPOINT.equals(path) ||
				WebSupport.XTB_ALTERNATE_METADATA_ENDPOINT.toLowerCase().equals(path);
	}

	public static Map<String, String> getHttpContext(HttpServletRequest request, NetworkConfig networkConfig) {
		Map<String, String> params = new HashMap<>();

		String userName = WebUtil.getParameter(WebSupport.USERNAME, request);
		if (userName != null) {
			params.put(WebSupport.USERNAME, userName);
		}
		if (networkConfig != null) {
			checkAndSetContext(request, params, networkConfig.getNetworkHeader());
		}
		checkAndSetContext(request, params, HttpHeaders.AUTHORIZATION);
		checkAndSetContext(request, params, HttpHeaders.USER_AGENT);
		checkAndSetContext(request, params, WebSupport.HTTP_REMOTE_USER);
		checkAndSetContext(request, params, HttpHeaders.REFERER);

		return params;
	}

	private static void checkAndSetContext(HttpServletRequest request, Map<String, String> params, String headerName) {
		String headerValue = WebUtil.getHeader(headerName, request);
		if (headerValue != null) {
			if (headerValue.length() > 1000) {
				headerValue = headerValue.substring(0, 999);
			}
			params.put(headerName, headerValue);
		}
	}

	private static HttpServletRequest getHttpServletRequest(boolean tryOnly) {
		var requestAttrs = getServletRequestAttributes(tryOnly);
		if (requestAttrs == null) {
			return null;
		}
		return requestAttrs.getRequest();
	}

	public static ServletRequestAttributes getServletRequestAttributes(boolean tryOnly) {
		var requestAttrs = RequestContextHolder.getRequestAttributes();
		if (requestAttrs instanceof ServletRequestAttributes servletRequestAttributes) {
			return servletRequestAttributes;
		}
		if (tryOnly) {
			return null;
		}
		throw new TechnicalException(String.format("Missing Spring RequestAttributes class=%s", requestAttrs));
	}

	public static <T> void setRequestAttribute(String key, T value, boolean tryOnly) {
		var request = getHttpServletRequest(tryOnly);
		if (request == null) {
			return;
		}
		request.setAttribute(key, value);
	}

	@SuppressWarnings("unchecked")
	public static <T> T getRequestAttribute(String key, boolean tryOnly) {
		var request = getHttpServletRequest(tryOnly);
		if (request == null) {
			return null;
		}
		return (T) request.getAttribute(key);
	}

	public static boolean canaryModeEnabled(HttpServletRequest httpRequest, NetworkConfig networkConfig) {
		if (networkConfig != null) {
			var canaryHeader = WebUtil.getHeader(networkConfig.getCanaryMarkerName(), httpRequest);
			var canaryCookie = WebUtil.getCookie(networkConfig.getCanaryMarkerName(), httpRequest);
			var enabledValue = networkConfig.getCanaryEnabledValue();
			return enabledValue.equals(canaryHeader) || enabledValue.equals(canaryCookie);
		}
		return false;
	}

}
