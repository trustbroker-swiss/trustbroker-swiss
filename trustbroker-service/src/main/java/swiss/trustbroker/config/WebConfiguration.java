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

package swiss.trustbroker.config;

import java.io.IOException;

import lombok.AllArgsConstructor;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.resource.PathResourceResolver;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.oidc.session.TomcatSessionManager;
import swiss.trustbroker.sessioncache.service.StateCacheService;

@Configuration
@AllArgsConstructor
public class WebConfiguration implements WebMvcConfigurer {

	private TrustBrokerProperties properties;

	@Override
	public void addCorsMappings(CorsRegistry registry) {
		// default CORS behavior, override in CorsSupport per OIDC client
		var corsOrigins = properties.getCors().getAllowedOrigins();
		var corsMethods = properties.getCors().getAllowedMethods();
		var corsHeaders = properties.getCors().getAllowedHeaders();
		registry.addMapping("/**")
				.allowedOrigins(corsOrigins.toArray(new String[0]))
				.allowedMethods(corsMethods.toArray(new String[0]))
				.allowedHeaders(corsHeaders.toArray(new String[0]));
	}

	@Override
	public void addResourceHandlers(ResourceHandlerRegistry registry) {
		registry.addResourceHandler("/**")
				.addResourceLocations("classpath:/static/")
				.resourceChain(true)
				.addResolver(new PathResourceResolver() {
					@Override
					protected Resource getResource(String resourcePath, Resource location) throws IOException {
						var requestedResource = location.createRelative(resourcePath);
						return requestedResource.exists() ? requestedResource : new ClassPathResource("/static/index.html");
					}
				});
	}

	// Make HTTP session manager K8S ready externalizing session to our StateCache DB
	// Idea contributed by https://github.com/hazelcast/hazelcast-tomcat-sessionmanager
	@Bean
	public WebServerFactoryCustomizer<TomcatServletWebServerFactory> customizeTomcat(
			TomcatSessionManager tomcatSessionManager) {
		return factory -> factory.addContextCustomizers(context ->
				context.setManager(tomcatSessionManager));
	}

	@Bean
	public TomcatSessionManager tomcatSessionManager(
			StateCacheService stateCacheService, RelyingPartyDefinitions relyingPartyDefinitions,
			TrustBrokerProperties trustBrokerProperties) {
		return new TomcatSessionManager(stateCacheService, relyingPartyDefinitions, trustBrokerProperties,
				trustBrokerProperties.getOidc().getSessionMode());
	}

}