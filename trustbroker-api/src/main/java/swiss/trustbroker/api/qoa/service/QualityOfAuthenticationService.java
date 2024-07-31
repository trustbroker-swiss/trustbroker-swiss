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

package swiss.trustbroker.api.qoa.service;

import swiss.trustbroker.api.qoa.dto.QualityOfAuthentication;

/**
 * Service for mapping between string based authentication levels / quality of authentication to numerical levels.
 * <br/>
 * An implementation can be configured via Spring @Value binding or by injecting swiss.trustbroker.config.TrustbrokerProperties
 * and using swiss.trustbroker.config.dto.QualityOfAuthenticationConfig (${trustbroker.config.qoa}).
 */
public interface QualityOfAuthenticationService {

	/**
	 * Conversion from a string representation to a QOA object.
	 * @param qualityOfAuthentication
	 * @return
	 */
	QualityOfAuthentication extractQoaLevel(String qualityOfAuthentication);

	/**
	 * @return a default level to be used as fallback if none was specified.
	 */
	QualityOfAuthentication getDefaultLevel();

	/**
	 *
	 * @return an object representing the unspecified level.
	 */
	QualityOfAuthentication getUnspecifiedLevel();

	// legacy, subject to change or removal

	default QualityOfAuthentication extractQoaLevelFromAuthLevel(String authenticationLevel) {
		return extractQoaLevel(authenticationLevel);
	}

	default QualityOfAuthentication getUnspecifiedAuthLevel() {
		return getUnspecifiedLevel();
	}

	default QualityOfAuthentication extractPepQoaFromAuthLevel(String authLevel, boolean kerberosLevelWorkaround) {
		return extractQoaLevelFromAuthLevel(authLevel);
	}
}
