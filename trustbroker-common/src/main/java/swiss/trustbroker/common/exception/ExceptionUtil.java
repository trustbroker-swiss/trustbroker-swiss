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

public class ExceptionUtil {

	private ExceptionUtil() { }

	// we want to have the root cause within the ERROR line as java stack-traces may not be aggregated in indexed logs
	public static Throwable getRootCause(Throwable ex) {
		if (ex != null) {
			while (ex.getCause() != null) {
				ex = ex.getCause();
			}
		}
		return ex;
	}

	// we want to have the root cause within the ERROR line as java stack-traces are not aggregated in indexed logs
	public static String getRootMessage(Throwable ex) {
		ex = getRootCause(ex);
		return (ex != null ? ex.getMessage() : null);
	}

}
