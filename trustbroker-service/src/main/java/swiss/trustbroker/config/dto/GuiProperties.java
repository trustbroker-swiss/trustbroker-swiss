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

package swiss.trustbroker.config.dto;

import java.util.ArrayList;
import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * GUI related configurations.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GuiProperties {

	/**
	 * Resource path where images used in the ClaimsProviderDefinitions are stored.
	 *
	 * @see swiss.trustbroker.federation.xmlconfig.ClaimsProviderDefinitions
	 */
	private String images;

	/**
	 * Resource path where UI language support files in JSON format are stored.
	 */
	private String translations;

	/**
	 * Resource path where theme assets are stored.
	 */
	private String themeAssets;

	/**
	 * Default language for the UI.
	 */
	private String defaultLanguage;

	/**
	 * Buttons enabled for the theme.
	 */
	@Builder.Default
	private List<GuiButtons> buttons = new ArrayList<>();

	/**
	 * Feature enabled for the theme.
	 */
	@Builder.Default
	private List<GuiFeatures> features = new ArrayList<>();

	/**
	 * Attributes for the cookie that stores the user's theme (if there is a theme selector).
	 */
	@Builder.Default
	private CookieProperties themeCookie = new CookieProperties();

	/**
	 * Attributes for the cookie that stores the user's selected language.
	 */
	@Builder.Default
	private CookieProperties languageCookie = new CookieProperties();

}
