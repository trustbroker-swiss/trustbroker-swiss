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

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Network configuration.
 *
 * @see swiss.trustbroker.federation.xmlconfig.ClaimsProviderRelyingParty
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NetworkConfig {

	private String mobileGatewayIpRegex;

	/**
	 * Name for the Intranet network used in configurations.
	 * <br/>
	 * Default: INTRANET
	 */
	@Builder.Default
	private String intranetNetworkName = "INTRANET";

	/**
	 * Name for the Internet network used in configurations.
	 * <br/>
	 * Default: INTERNET
	 */
	@Builder.Default
	private String internetNetworkName = "INTERNET";

	/**
	 * HTTP header delivering the client network.
	 * Usually sent by load balancer
	 * <br/>
	 * Default: Client_Network (should be X-Client-Network)
	 */
	@Builder.Default
	private String networkHeader = "Client_Network";

	/**
	 * HTTP header for simulating the client network.
	 * Sent by test agents to test HRD rules.
	 * <br/>
	 * Default: "X-Simulated-Client-Network
	 */
	@Builder.Default
	private String testNetworkHeader = "X-Simulated-Client-Network";

	public boolean isIntranet(String name) {
		return intranetNetworkName != null && intranetNetworkName.equals(name);
	}

	public boolean isInternet(String name) {
		return internetNetworkName != null && internetNetworkName.equals(name);
	}

}
