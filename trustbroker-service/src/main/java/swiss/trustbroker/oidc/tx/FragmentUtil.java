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
package swiss.trustbroker.oidc.tx;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import swiss.trustbroker.util.ApiSupport;

// spring-security does not handle fragment mode properly, so we patch it outside until that's fixed
// we need to remember the fact across a fill federation execution from /authorize to the application code redirect.
@Slf4j
public class FragmentUtil {

	public static final String OIDC_RESPONSE_MODE = "response_mode";

	public static final String OIDC_RESPONSE_FRAGMENT = "fragment";

	private FragmentUtil() {
	}

	public static boolean isFragmentResponseMode(String responseType) {
		return OIDC_RESPONSE_FRAGMENT.equals(responseType);
	}

	static void checkAndRememberFragmentMode(HttpServletRequest request) {
		var session = request.getSession(false);
		if (session == null) {
			return;
		}
		if (isFragmentResponseMode(request.getParameter(OIDC_RESPONSE_MODE))) {
			log.debug("Handling fragment response_type on session={}", session);
			session.setAttribute(OIDC_RESPONSE_MODE, OIDC_RESPONSE_FRAGMENT);
		}
		// make sure we keep the fragment mode across the federated login
		else if (ApiSupport.isOidcAuthPath(request.getPathInfo())) {
			removeFragmentModeFlag(session);
		}
	}

	static String checkAndFixFragmentMode(String redirect, HttpSession session, String responseMode) {
		if (redirect != null) {
			if (redirect.contains("?code=") && session != null && OIDC_RESPONSE_FRAGMENT.equals(
					session.getAttribute(OIDC_RESPONSE_MODE))) {
				log.debug("Handling code redirect switch to fragment on session={}", session);
				removeFragmentModeFlag(session);
				return redirect.replace("?code=", "#code=");
			}
			if (redirect.contains("?error=") && OIDC_RESPONSE_FRAGMENT.equals(responseMode)) {
				log.debug("Handling error redirect switch to fragment on={}", redirect);
				return redirect.replace("?error=", "#error=");
			}
		}
		return redirect;
	}

	// prevent storing session by checking on attribute existence
	private static void removeFragmentModeFlag(HttpSession session) {
		if (session.getAttribute(OIDC_RESPONSE_MODE) != null) {
			session.removeAttribute(OIDC_RESPONSE_MODE);
		}
	}

}
