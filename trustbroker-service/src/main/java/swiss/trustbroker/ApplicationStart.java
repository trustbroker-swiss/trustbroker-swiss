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

package swiss.trustbroker;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.common.server.ApplicationMain;
import swiss.trustbroker.exception.GlobalExceptionHandler;

/**
 * Initialize everything before starting spring container, especially libraries using statics.
 */
@Slf4j
public class ApplicationStart extends ApplicationMain {

	public ApplicationStart(Class<?> starterClass, String[] args) {
		super(starterClass, args);
	}

	@Override // add wS/WSS4J to the mix
	protected void initSamlSubSubsystem() {
		// pre-initialize everything not handled by spring setup
		SamlInitializer.initSamlSubSystem();
	}

	@Override
	protected void logException(Throwable ex) {
		GlobalExceptionHandler.logException(ex,  null);
	}

	@Override
	protected void runApplication() {
		SpringApplication.run(starterClass, args);
	}

	public static void runBootstrap(Class<?> starterClass, String[] args) {
		try {
			var main = new ApplicationStart(starterClass, args);
			main.runBootstrap();
		}
		catch (Exception ex) {
			// constructor can throw an exception when ENV variables are not correctly defined
			GlobalExceptionHandler.logException(ex, null);
		}
	}

}
