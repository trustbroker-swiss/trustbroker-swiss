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

import lombok.extern.slf4j.Slf4j;

/**
 * Configuration enabling toggle.
 * <br/>
 * Values can be configured in any case. Lower case is recommended for consistency with other true/false flags.
 */
@Slf4j
public enum FeatureEnum {
	/**
	 * Enabled
	 */
	TRUE,

	/**
	 * Disabled. XTB will load and validate the configuration, but not use it.
	 */
	FALSE,

	/**
	 * Configuration invalid or not yet ready for enabling. XTB will not load the config.
	 */
	INVALID;

	public static FeatureEnum ofName(String name) {
		if (name == null) {
			return TRUE;
		}
		try {
			return FeatureEnum.valueOf(name.toUpperCase());
		}
		catch (IllegalArgumentException ex) {
			log.error("Invalid FeatureEnum value={} msg={} - using INVALID", name, ex.getMessage());
			return INVALID;
		}
	}

	public static String getName(FeatureEnum feature) {
		return feature == null ? FeatureEnum.TRUE.name() : feature.name();
	}
}
