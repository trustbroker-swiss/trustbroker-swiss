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
package swiss.trustbroker.common.util;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.sameInstance;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

class CollectionUtilTest {

	@Test
	void asCollection() {
		assertThat(CollectionUtil.asCollection(null), is(Collections.emptyList()));
		var str = "test";
		assertThat(CollectionUtil.asCollection(str), is(List.of(str)));
		var set = Set.of(str);
		assertThat(CollectionUtil.asCollection(set), is(sameInstance(set)));
	}

	@Test
	void asList() {
		assertThat(CollectionUtil.asList(null), is(Collections.emptyList()));
		var str = "test";
		assertThat(CollectionUtil.asList(str), is(List.of(str)));
		var set = Set.of(str);
		assertThat(CollectionUtil.asList(set), is(List.of(str)));
		var list = List.of(str);
		assertThat(CollectionUtil.asList(list), is(sameInstance(list)));
	}


	@Test
	void asMap() {
		var key = "key";
		var value = "value";
		var oldValue = "oldValue";
		var map = Map.of(key, value);
		assertThat(CollectionUtil.asMap(null, null, map), is(sameInstance(map)));
		assertThat(CollectionUtil.asMap(key, value, map), is(sameInstance(map)));
		assertThat(CollectionUtil.asMap(key, value, oldValue), is(Map.of(key, value)));
	}

}
