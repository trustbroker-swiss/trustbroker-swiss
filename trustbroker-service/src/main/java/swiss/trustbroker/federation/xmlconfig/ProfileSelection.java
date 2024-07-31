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

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlValue;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import swiss.trustbroker.api.profileselection.dto.ProfileSelectionProperties;

/**
 * Configures the profile selection.
 *
 * @see swiss.trustbroker.api.profileselection.service.ProfileSelectionService
 */
@XmlRootElement(name = "ProfileSelection")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProfileSelection implements Serializable, ProfileSelectionProperties {

	/**
	 * Enable this feature
	 */
	@XmlAttribute(name = "enabled")
	private Boolean enabled;

	/**
	 * Apply name/value transformation.
	 * <br/>
	 * Default: false
	 */
	@XmlAttribute(name = "n2k")
	@Builder.Default
	private Boolean needToKnow = Boolean.FALSE;

	/**
	 * Apply name/value transformation for n2k only for Oidc.
	 * <br/>
	 * Default: true, disable if SAML should also be done
	 */
	@XmlAttribute(name = "oidcOnly")
	@Builder.Default
	private Boolean oidcOnly = Boolean.TRUE;

	/**
	 * Apply name/value transformation for CustomProperties (if true regardless of n2k).
	 * <br/>
	 * Set to false if for n2k=true to leave custom profile props alone.
	 */
	@XmlAttribute(name = "customizeProperties")
	private Boolean customizeProperties;

	/**
	 * Apply name/value transformation for UnitProperties if n2k=true.
	 * <br/>
	 * Default: false
	 */
	@XmlAttribute(name = "customizeUnits")
	@Builder.Default
	private Boolean customizeUnits = Boolean.FALSE;

	/**
	 * Filter unit properties by selected/default profile ID if n2k=true.
	 * <br/>
	 * Default: false
	 */
	@XmlAttribute(name = "filterUnits")
	@Builder.Default
	private Boolean filterUnits = Boolean.FALSE;

	/**
	 * Mode for profile selection.
	 */
	@XmlValue
	private ProfileSelectionMode mode;

	@JsonIgnore
	@Override
	public boolean isEnabled() {
		return Boolean.TRUE.equals(enabled);
	}

	@JsonIgnore
	@Override
	public String getProfileSelectionMode() {
		return mode != null ? mode.name() : null;
	}

	@JsonIgnore
	@Override
	public boolean isOidcOnly() {
		return Boolean.TRUE.equals(oidcOnly);
	}

	@JsonIgnore
	@Override
	public boolean isN2kEnabled() {
		return Boolean.TRUE.equals(needToKnow);
	}

	@JsonIgnore
	@Override
	public boolean isTransformCustomPropsEnabled() {
		return (isN2kEnabled() && customizeProperties == null) // n2k=true sufficient for all transformations
				|| Boolean.TRUE.equals(customizeProperties); // explicitly set to true when n2k=false
	}

	@JsonIgnore
	@Override
	public boolean isTransformUnitPropsEnabled() {
		return isN2kEnabled() && Boolean.TRUE.equals(customizeUnits);
	}

	@JsonIgnore
	@Override
	public boolean isFilterUnitPropsEnabled() {
		return isN2kEnabled() && Boolean.TRUE.equals(filterUnits);
	}

}
