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

import java.io.Serializable;
import java.sql.Timestamp;
import java.util.Collections;
import java.util.Set;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SsoParticipants implements Serializable {

	public static final SsoParticipants UNDEFINED = SsoParticipants.builder()
			.ssoGroupName("").participants(Collections.emptySet()).build();

	private String ssoGroupName;

	private String ssoSubject;

	private Timestamp ssoEstablishedTime;

	private Timestamp expirationTime;

	private Set<SsoParticipant> participants;

}
