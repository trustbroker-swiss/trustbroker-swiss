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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class CollectionUtil {

	private CollectionUtil() {
	}

	// returns value converted to (empty if null) list if needed
	@SuppressWarnings("unchecked")
	public static List<Object> asList(Object value) {
		if (value == null) {
			return Collections.emptyList();
		}
		if (value instanceof List<?> list) {
			return (List<Object>) list;
		}
		if (value instanceof Collection<?> collection) {
			return new ArrayList<>(collection);
		}
		var list = new ArrayList<>();
		list.add(value);
		return list;
	}

	// returns oldValue if a Map or else map of name => value (either oldValue or both name and value need to be non-null)
	@SuppressWarnings("unchecked")
	public static Map<String, Object> asMap(String name, Object value, Object oldValue) {
		if (oldValue instanceof Map<?, ?> map) {
			return (Map<String, Object>) map;
		}
		return Map.of(name, value);
	}

	// returns value converted to (empty if null) collection if needed
	@SuppressWarnings("unchecked")
	public static Collection<Object> asCollection(Object value) {
		if (value == null) {
			return Collections.emptyList();
		}
		if (value instanceof Collection<?> collection) {
			return (Collection<Object>) collection;
		}
		var list = new ArrayList<>();
		list.add(value);
		return list;
	}

	// Immutable List.of used everywhere
	public static List<String> addToListIfNotExist(List<String> queryResponseValues, List<String> values) {
		var result = new ArrayList<>(queryResponseValues);
		for (var value : values) {
			if (!queryResponseValues.contains(value)) {
				result.add(value);
			}
		}
		return result;
	}
}
