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

package swiss.trustbroker.qoa.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import swiss.trustbroker.api.qoa.dto.QualityOfAuthentication;

/**
 * NO-OP fallback implementation of QualityOfAuthentication, provides single default level.
 *
 * @see QualityOfAuthentication
 */
@AllArgsConstructor
@Getter
public enum NoOpQoa implements QualityOfAuthentication {

	STRONGEST_POSSIBLE("strongest_possible", -2),
	UNSPECIFIED("unspecified", -1),
	DEFAULT("default", 0);

	private String name;

	private int level;

	@Override
	public boolean isStrongestPossible() {
		return this == STRONGEST_POSSIBLE;
	}

	@Override
	public boolean isRegular() {
		return this == DEFAULT;
	}

	@Override
	public boolean isUnspecified() {
		return this == UNSPECIFIED;
	}

}
