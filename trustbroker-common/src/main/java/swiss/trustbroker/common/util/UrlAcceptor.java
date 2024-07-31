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

import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

@Slf4j
public class UrlAcceptor {

	@SuppressWarnings("java:S1075")
	private static final String SUBPATH_MATCH = "/.*";

	private UrlAcceptor() {
	}

	// Check HTTP Origin header against configured ACLs
	public static boolean isTrustedOrigin(String origin, Set<String> acUrls) {
		return isUrlOkForAccess(origin, acUrls, true);
	}

	public static boolean isRedirectUrlOkForAccess(String requestedRedirectUri, Set<String> acUrls) {
		return isUrlOkForAccess(requestedRedirectUri, acUrls, false);
	}

	private static boolean isUrlOkForAccess(String check, Set<String> acUrls, boolean ignorePath) {
		if (check == null || acUrls == null) {
			return false;
		}
		try {
			var uri = new URI(check);
			if (isLocalhostAccess(uri.getHost())) {
				return localhostUrlOkForAccess(check, acUrls, ignorePath);
			}
		}
		catch (URISyntaxException | NullPointerException e) {
			log.error("Invalid url={} ({})", check, e.getMessage());
		}
		return acUrls.stream().anyMatch(acuri -> isUrlOkForAccess(check, acuri, ignorePath));
	}

	public static boolean isRedirectUrlOkForAccess(String requestedRedirectUri, List<URI> acUrls) {
		if (requestedRedirectUri != null || acUrls != null) {
			var acUrlsSet = acUrls.stream().map(URI::toString).collect(Collectors.toSet());
			return isRedirectUrlOkForAccess(requestedRedirectUri, acUrlsSet);
		}
		return false;
	}

	// Check URLs including localhost special semantics but accept regexp on path and /.* as not having a sub-path,
	// so we do not have to configure https:/host/.* and https://host twice.
	public static boolean isUrlOkForAccess(URI check, URI accept) {
		return isUrlOkForAccess(check, accept, false);
	}

	public static boolean isUrlOkForAccessIgnoringPath(URI check, URI accept) {
		return isUrlOkForAccess(check, accept, true);
	}

	private static boolean isUrlOkForAccess(URI check, URI accept, boolean ignorePath) {
		if (check == null || accept == null) {
			return false;
		}
		var isLocalHost = isLocalhostAccess(check.getHost());
		return // no relative URLs allowed
				check.isAbsolute() && accept.isAbsolute() &&
						isSchemeMatching(check, accept) &&
						isHostMatching(check, accept, isLocalHost) &&
						isPortMatching(check, accept, isLocalHost) &&
						(ignorePath || isPathMatching(check, accept));
	}

	// protocol must match exactly
	private static boolean isSchemeMatching(URI check, URI accept) {
		return check.getScheme().equals(accept.getScheme());
	}

	// host must match exactly or both must be localhost addresses
	private static boolean isHostMatching(URI check, URI accept, boolean isLocalHost) {
		return check.getHost().equals(accept.getHost())
				|| (isLocalHost && isLocalhostAccess(accept.getHost()));
	}

	// port must match if not default or not 0 signaling any port on localhost
	private static boolean isPortMatching(URI check, URI accept, boolean isLocalHost) {
		return check.getPort() == accept.getPort()
				|| check.getPort() == HttpUtil.getDefaultPort(accept)
				|| accept.getPort() == HttpUtil.getDefaultPort(check)
				|| (isLocalHost && accept.getPort() == 0);
	}

	// path must match by regexp including /.* or without it (top-level resource access allowed)
	private static boolean isPathMatching(URI check, URI accept) {
		return check.getPath().equals(accept.getPath())
				|| (check.getPath() + SUBPATH_MATCH).equals(accept.getPath()) // handle exact match without a trailing /
				|| check.getPath().matches(accept.getPath());
	}

	static boolean isUrlOkForAccess(String check, String accept, boolean ignorePath) {
		try {
			return isUrlOkForAccess(new URI(check), new URI(accept), ignorePath);
		}
		catch (URISyntaxException | NullPointerException e) {
			log.error("Deny invalid url={} checked against acUrl={} ({})", check, accept, e.getMessage());
			return false;
		}
	}

	// Inspired by OAuth2AuthorizationCodeRequestAuthenticationValidator.isLoopbackAddress
	private static boolean isLocalhostAccess(String host) {
		if (!StringUtils.hasText(host)) {
			return false;
		}
		if (host.equals("localhost")) {
			return true; // speed up as DNS lookups are expensive
		}
		// handle IP addresses too even though we cannot see if the client was manipulated to forward localhost to bad server
		try {
			// map to IP (expensive, local DNS cache lookup at least for any redirect URL we get)
			var inetAddress = InetAddress.getByName(host);
			var hostIp = inetAddress.getHostAddress();

			// IPv6 loopback address should either be "0:0:0:0:0:0:0:1" or "::1"
			if ("[0:0:0:0:0:0:0:1]".equals(hostIp) || "[::1]".equals(hostIp)) {
				return true;
			}
			// IPv4 loopback address ranges from 127.0.0.1 to 127.255.255.255
			var ipv4Octets = hostIp.split("\\.");
			if (ipv4Octets.length != 4) {
				return false;
			}
			var address = new int[ipv4Octets.length];
			for (int i = 0; i < ipv4Octets.length; i++) {
				address[i] = Integer.parseInt(ipv4Octets[i]);
			}
			return address[0] == 127 && address[1] >= 0 && address[1] <= 255 && address[2] >= 0 &&
					address[2] <= 255 && address[3] >= 1 && address[3] <= 255;
		}
		catch (Exception ex) {
			// info would be interesting, but we cannot assume that service has the clients DNS resolv.conf
			log.debug("Handling host={} for localhost check failed with exception: {}", host, ex.getMessage());
			return false;
		}
	}

	// accept http://localhost/.* as http://localhost too and also handle default ports
	private static boolean localhostUrlOkForAccess(String check, String aclUri, boolean ignorePath) {
		return check.matches(aclUri) // regexp match only
				|| check.matches(aclUri.replace(SUBPATH_MATCH, "")) // regexp match but skip sub-path
				|| isUrlOkForAccess(check, aclUri, ignorePath); // OIDC check aligned with SAML check
	}

	// Use regex validation for localhost URLs of type https?://localhost:?(.*?)/?
	private static boolean localhostUrlOkForAccess(String check, Set<String> aclUris, boolean ignorePath) {
		return check != null && aclUris != null &&
				aclUris.stream().anyMatch(configUri -> localhostUrlOkForAccess(check, configUri, ignorePath));
	}

}
