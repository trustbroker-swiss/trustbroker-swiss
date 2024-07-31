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

package swiss.trustbroker.samlmock;

import java.time.Duration;
import java.util.Optional;

import org.apache.velocity.app.VelocityEngine;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import swiss.trustbroker.common.saml.service.ArtifactCacheService;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.setup.service.GitService;
import swiss.trustbroker.common.util.DirectoryUtil;

@Configuration
public class SamlMockConfiguration {

	@Bean
	public GitService gitService() {
		return new GitService(new DirectoryUtil());
	}

	@Bean
	public static VelocityEngine velocityEngine() {
		return OpenSamlUtil.createVelocityEngine(null);
	}

	@Bean
	public static ArtifactCacheService artifactCacheService() {
		return new ArtifactCacheService(Optional.empty(), Duration.ofMinutes(5), Duration.ofMinutes(10));
	}
}
