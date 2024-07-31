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

package swiss.trustbroker.exception;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class GlobalExceptionHandlerTest {

	@ParameterizedTest
	@CsvSource(value = { "1", "2", "3" })
	void getRootCause(int levels) {
		var ex = buildExceptionChain(levels, true);
		var result = GlobalExceptionHandler.getRootCause(ex);
		assertThat(result, is(not(nullValue())));
		assertThat(result.getMessage(), is("Level 1"));
	}

	@ParameterizedTest
	@CsvSource(value = { "1", "2", "3" })
	void getMessageOfExceptionOrCause(int levels) {
		var ex = buildExceptionChain(levels, false);
		var result = GlobalExceptionHandler.getMessageOfExceptionOrCause(ex, false);
		assertThat(result, is("Level 1"));
	}

	@ParameterizedTest
	@CsvSource(value = { "1", "2", "3" })
	void getMessageOfExceptionOrCauseWithToString(int levels) {
		var ex = buildExceptionChain(levels, false);
		var result = GlobalExceptionHandler.getMessageOfExceptionOrCause(ex, true);
		if (levels == 1) {
			assertThat(result, is(ex.getMessage()));
		}
		else {
			assertThat(result, is("java.lang.Exception: Level 1"));
		}
	}

	@Test
	void getMessageOfExceptionOrCauseWithMessage() {
		var ex = buildExceptionChain(2, true);
		var result = GlobalExceptionHandler.getMessageOfExceptionOrCause(ex, false);
		assertThat(result, is(ex.getMessage()));
	}

	private Exception buildExceptionChain(int levels, boolean messageForAll) {
		// root cause is always level 1
		Exception cause = null;
		for (int ii = 1; ii <= levels; ++ii) {
			String message = null;
			if (messageForAll || ii == 1) {
				message = "Level " + ii;
			}
			cause = new Exception(message, cause);
		}
		return cause;
	}

}
