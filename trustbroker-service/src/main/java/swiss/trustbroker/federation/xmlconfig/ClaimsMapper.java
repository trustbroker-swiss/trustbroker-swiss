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

package swiss.trustbroker.federation.xmlconfig;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.EnumUtils;

/**
 * Mapping of OIDC/SAML claims.
 */
@Slf4j
public enum ClaimsMapper {

	/**
	 * Maps ISO-8601 datetime or instant string to epoc seconds.
 	 */
	TIME_EPOCH {

		public Object map(Object value) {
			if (value instanceof String valueStr) {
				try {
					return Instant.parse(valueStr).getEpochSecond();
				}
				catch (DateTimeParseException ex) {
					try {
						return DateTimeFormatter.ISO_DATE_TIME.parse(valueStr, Instant::from).getEpochSecond();
					}
					catch (DateTimeParseException ex2) {
						log.info("Cannot parse value=\"{}\" as ISO-8601 datetime or instant ex1=\"{}\" ex2=\"{}\"",
								value, ex.getMessage(), ex2.getMessage());
					}
				}
			}
			else if (value instanceof Instant valueInstant) {
				return valueInstant.getEpochSecond();
			}
			else if (value instanceof Date valueDate) {
				return TimeUnit.MILLISECONDS.toSeconds(valueDate.getTime());
			}
			unexpectedValue(value, this.name());
			return value;
		}

	},

	/**
	 * Maps "true"/"false" (case-insensitive) to Boolean.
 	 */
	BOOLEAN {

		public Object map(Object value) {
			if (value instanceof String valueStr) {
				if (valueStr.equalsIgnoreCase("true")) {
					return Boolean.TRUE;
				}
				if (valueStr.equalsIgnoreCase("false")) {
					return Boolean.FALSE;
				}
			}
			else if (value instanceof Boolean) {
				return value;
			}
			unexpectedValue(value, this.name());
			return value;
		}

	},

	/**
	 * Maps swiss social security number to Long:<br/>
	 * three digits (currently always 756) optional dot, 4 digits, optional dot, 4 digits, optional dot, 2 digits.
 	 */
	SWISS_SOCIAL_SECURITY_NO {

		private static final Pattern PATTERN = Pattern.compile("\\d\\d\\d[.]?\\d\\d\\d\\d[.]?\\d\\d\\d\\d[.]?\\d\\d");

		public Object map(Object value) {
			if (value instanceof String valueStr) {
				if (PATTERN.matcher(valueStr).matches()) {
					valueStr = valueStr.replace(".", "");
					// must be parseable as long now
					return Long.parseLong(valueStr);
				}
			}
			else if (value instanceof Number) {
				return value;
			}
			unexpectedValue(value, this.name());
			return value;
		}

	},

	/**
	 * Runs a Groovy script to perform the mapping: name-converter.groovy
	 */
	SCRIPT {
		// must be done post-processing as we do not have a ScriptService here and script name needs to be derived
		public Object map(Object value) {
			return value;
		}
	},

	/**
	 * Normalize emails dropping duplicates (same value from different sources).
	 * Experimental: RFC 5321 actually says mails can have a case-sensitive local-part but in practice it's case insensitive.
	 */
	EMAIL {
		public Object map(Object value) {
			return value == null ? null : value.toString().toLowerCase();
		}
	};

	public abstract Object map(Object value);

	@SuppressWarnings("java:S1168") // mapper does not know the semantics of the list, hence it must map a null list to null
	public List<Object> map(List<Object> values) {
		if (values == null) {
			return null;
		}
		// optionally make value unique for some mapper types
		return optionalUnique(values.stream().map(this::map).toList());
	}

	private List<Object> optionalUnique(List<Object> values) {
		if (this.equals(EMAIL)) {
			return values.stream()
					.distinct()
					.toList();
		}
		return values;
	}

	private static void unexpectedValue(Object value, String mapper) {
		if (value != null) {
			log.info("Invalid value=\"{}\" of type={} for oidcMapper={} returning unchanged",
					value, value.getClass().getName(), mapper);
		}
	}

	public static ClaimsMapper of(String name) {
		var result = EnumUtils.getEnum(ClaimsMapper.class, name);
		if (result == null) {
			log.error("Invalid mapper={} allowedValues={}", name, values());
		}
		return result;
	}

}
