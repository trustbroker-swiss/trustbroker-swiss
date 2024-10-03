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

package swiss.trustbroker.qoa.service;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.EnumUtils;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.stereotype.Service;
import swiss.trustbroker.api.qoa.dto.QualityOfAuthentication;
import swiss.trustbroker.api.qoa.service.QualityOfAuthenticationService;
import swiss.trustbroker.qoa.dto.NoOpQoa;

/**
 * NO-OP fallback implementation of QualityOfAuthenticationService based on NoOpQoa.
 *
 * @see QualityOfAuthenticationService
 */
@Service
@ConditionalOnMissingBean(QualityOfAuthenticationService.class)
@Slf4j
public class NoOpQualityOfAuthenticationService implements QualityOfAuthenticationService {

	@Override
	public QualityOfAuthentication extractQoaLevel(String qualityOfAuthentication) {
		return EnumUtils.getEnum(NoOpQoa.class, qualityOfAuthentication, NoOpQoa.UNSPECIFIED);
	}

	@Override
	public QualityOfAuthentication getDefaultLevel() {
		return NoOpQoa.DEFAULT;
	}

	@Override
	public QualityOfAuthentication getUnspecifiedLevel() {
		return NoOpQoa.UNSPECIFIED;
	}
}
