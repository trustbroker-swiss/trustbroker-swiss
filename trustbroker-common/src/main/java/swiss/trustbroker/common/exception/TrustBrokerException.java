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

package swiss.trustbroker.common.exception;

import lombok.Getter;

@Getter
public abstract class TrustBrokerException extends RuntimeException {

	// improve debuggability by exposing internal message when enabled via logging facility
	@SuppressWarnings("java:S1165")
	private static boolean debug = false;

	private final ErrorCode errorCode;

	private final String internalMessage;

	protected TrustBrokerException(String message, String internalMessage) {
		this(message, null, internalMessage, null);
	}

	protected TrustBrokerException(String message, ErrorCode errorCode, String internalMessage,
			Throwable exception) {
		super(debug ? message + ": " + internalMessage : message, exception);
		this.errorCode = errorCode;
		this.internalMessage = internalMessage;
	}

	// Improve error handling in unit tests - not thread safe, do not use in production code!
	public static void enableDebugging() {
		debug = true;
	}

}
