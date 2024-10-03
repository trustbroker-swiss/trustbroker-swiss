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

package swiss.trustbroker.saml.dto;

import java.util.ArrayList;
import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderRelyingParty;

/**
 * Class is used to implement the contract towards ScriptService on RP request processing side.
 * See CpResponse class for counterpart on CP side.
 */
@Data
@EqualsAndHashCode(callSuper=false)
@Builder
@NoArgsConstructor
@AllArgsConstructor
@SuppressWarnings("java:S2250") // all the lists in here are small
@Slf4j
public class RpRequest extends ResponseStatus {

	private String referer; // from the incoming HTTP request

	private String rpIssuer;// from the incoming SAML request

	private String requestId; // ID of the incoming message (e.g. AuthnRequest)

	private String applicationName; // e.g. from AuthnRequest.ProviderName

	@Builder.Default
	private List<String> contextClasses = new ArrayList<>();

 	@Builder.Default
	private boolean useSkinnyHrdScreen = false; // allow to use a non-angular version of the HRD screen

	@Builder.Default
	private List<ClaimsProviderRelyingParty> claimsProviders = new ArrayList<>();

	@Builder.Default
	private List<UiObject> uiObjects = new ArrayList<>();

	public ClaimsProviderRelyingParty getClaimsProvider(String id) {
		return claimsProviders.stream().filter(cp -> cp.getId().equals(id)).findFirst().orElse(null);
	}

	// HRD: Federation to single CP possible
	public boolean hasSingleClaimsProvider() {
		return 	claimsProviders.size() == 1; // uiObjects might still be empty because rendering phase was skipped
	}

	public int getClaimsProvidersCount() {
		return claimsProviders.size();
	}

	// HRD: Manually construct a HRD tile
	public void  addUiElement(UiObject uiObject) {
		uiObjects.add(uiObject);
	}

	// HRD: Remove a specific one
	public ClaimsProviderRelyingParty dropClaimsProvider(String id) {
		var ret = getClaimsProvider(id);
		if (ret != null) {
			claimsProviders.remove(ret);
		}
		return ret;
	}

	// HRD: Retain a specific one to automatically dispatch
	public ClaimsProviderRelyingParty retainClaimsProvider(String id) {
		var ret = getClaimsProvider(id);
		if (ret != null) {
			claimsProviders.clear();
			claimsProviders.add(ret);
		}
		return ret;
	}

	// QoA handling
	public boolean hasContextClass(String contextClass) {
		return contextClasses.contains(contextClass);
	}

	public boolean addContextClass(String contextClass) {
		if (!hasContextClass(contextClass)) {
			contextClasses.add(contextClass);
			return true;
		}
		return false;
	}

	public boolean removeContextClass(String contextClass) {
		return contextClasses.remove(contextClass);
	}

}
