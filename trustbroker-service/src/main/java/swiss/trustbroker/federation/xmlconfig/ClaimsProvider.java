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

import java.io.Serializable;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlRootElement;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Defines the display on the HRD screen of a ClaimsProvider (CP).
 *
 * @see ClaimsParty
 */
@XmlRootElement(name = "ClaimsProvider")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ClaimsProvider implements Serializable {

	/**
	 * ID of the CP referenced by RP setups (HRD).
	 */
	@XmlAttribute(name = "id")
	private String id;

	/**
	 * Free name, it's recommended to use a unique name.
	 */
	@XmlAttribute(name = "name")
	private String name;

	/**
	 * Image displayed in the HRD large view.
	 */
	@XmlAttribute(name = "img")
	private String img;

	/**
	 * Image displayed in the small view. This feature was removed and replaced by shortcut/color rendering.
	 */
	@XmlAttribute(name = "button")
	private String button;

	/**
	 * Text displayed to the user as part of the CP tile.
	 * <br/>
	 * The fallback order (if not defined) is: description > name > title > ID
	 */
	@XmlAttribute(name = "description")
	private String description;

	/**
	 * Tile for the CP title.
	 * <br/>
	 * The fallback order (if not defined) is: title > name > description > ID
	 */
	@XmlAttribute(name = "title")
	private String title;

	/**
	 * A usually two-character code identifying the CP on small screens.
	 */
	@XmlAttribute(name = "shortcut")
	private String shortcut;

	/**
	 * An HTML color code identifying the CP on small screens.
	 */
	@XmlAttribute(name = "color")
	private String color;

}
