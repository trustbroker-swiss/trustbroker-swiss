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

package swiss.trustbroker.audit.service;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import swiss.trustbroker.audit.dto.AuditDto;
import swiss.trustbroker.audit.dto.CustomLogging;

/**
 * Build log entry for audit log in expected format: <code>key=value[,key=value ...]</code>. Value is enclosed in double quotes if
 * needed (currently: if not alphanumeric or underscore). Double quotes in value escaped with a backslash. <br/> A postfix can be
 * added in the value (used for fully qualified names): <code>key="value (postfix)"</code> <br/> Dashes in the key name are
 * replaced with underscores to comply with Splunk key requirements.
 */
public class AuditLogBuilder {

	// https://docs.splunk.com/Documentation/Splunk/latest/Data/Configureindex-timefieldextraction
	// (values might allow more characters without quoting)
	private static final Pattern KEY_NAME_PATTERN = Pattern.compile("\\w*");

	private final StringBuilder output = new StringBuilder();

	private final int prefixLength;

	private final List<Field> dtoFields;

	public AuditLogBuilder() {
		this(null);
	}

	public AuditLogBuilder(String prefix) {
		if (prefix != null) {
			output.append(prefix);
		}
		prefixLength = output.length();
		dtoFields = initDtoFields();
	}

	@SuppressWarnings("java:S3011") // modifying field accessibility in local dto package
	private static List<Field> initDtoFields() {
		// operates on a copy of the declared fields and makes them accessible for this class
		List<Field> dtoFieldList = new ArrayList<>();
		for (Field field : AuditDto.class.getDeclaredFields()) {
			// saml fields need special handling
			if (field.getAnnotation(CustomLogging.class) == null) {
				field.setAccessible(true);
				dtoFieldList.add(field);
			}
		}
		return dtoFieldList;
	}

	// not used for OIDC
	private static boolean isAuditAddonsEnabled(String postfix, AuditDto.AttributeSource source) {
		return AuditLogger.isAdditionalAuditingEnabled() && // DEBUG
				(StringUtils.isNotEmpty(postfix)  // SAML name
						|| (source != null && StringUtils.isNotEmpty(source.getShortName()))); // SAML value
	}

	/**
	 * Append key/value pair in the format specified above.
	 *
	 * @param key     nothing appended if null (should not happen in practice)
	 * @param value   nothing appended if null (i.e. skip key if no value present)
	 * @param postfix appended after value if not null or empty
	 * @return this
	 */
	public AuditLogBuilder append(String key, Object value, String postfix, AuditDto.AttributeSource source, long count) {
		if (key == null || value == null) {
			return this;
		}
		if (output.length() > prefixLength) {
			output.append(", ");
		}
		// some AttributeNames contain dash, which is not allowed as Splunk key character for indexing -> replace to avoid quotes
		appendEncoded(key.replace('-', '_'));
		output.append('=');
		StringBuilder valueBuilder = new StringBuilder(valueToString(value));
		// if not INFO we append the FQ name to see from which attribute this was mapped plus some stats
		if (isAuditAddonsEnabled(postfix, source)) {
			valueBuilder.append(" (");
			var separator = "";
			if (source != null) {
				valueBuilder.append('@');
				valueBuilder.append(source.getShortName());
				separator = " ";
			}
			if (count > 1) {
				valueBuilder.append(separator);
				valueBuilder.append(count);
				separator = " ";
			}
			if (postfix != null) {
				valueBuilder.append(separator);
				valueBuilder.append(postfix);
			}
			valueBuilder.append(')');
		}
		appendEncoded(valueBuilder.toString());
		return this;
	}

	public AuditLogBuilder append(String key, Object value, String postfix) {
		return append(key, value, postfix, null, 1);
	}

	private void appendEncoded(String value) {
		String valueStr = value.replace("\"", "\\\"");
		boolean simpleValue = KEY_NAME_PATTERN.matcher(valueStr).matches();
		if (!simpleValue) {
			output.append('"');
		}
		output.append(valueStr);
		if (!simpleValue) {
			output.append('"');
		}
	}

	public AuditLogBuilder append(String key, Object value) {
		return append(key, value, null);
	}

	private static String valueToString(Object value) {
		if (value instanceof Collection) {
			Collection<?> col = (Collection<?>) value;
			if (col.size() == 1) {
				// name="value1" in Splunk
				return String.valueOf(col.iterator().next());
			}
			if (col.isEmpty()) {
				// null or empty string better for Splunk? null could be a value produced before so use name="" for now
				return "";
			}
			// else: name="[value1, value2]" in Splunk (for sets/lists - for maps {key1=value1 key2=value2} -> not yet used)
		}
		return String.valueOf(value);
	}

	/**
	 * append all fields of the AuditDto
	 *
	 * @param auditDto
	 * @return this
	 */
	public AuditLogBuilder appendDtoFields(AuditDto auditDto) {
		if (auditDto == null) {
			return this;
		}
		dtoFields.forEach(field -> {
			try {
				appendField(field.getName(), field.get(auditDto));
			}
			catch (IllegalAccessException ex) {
				// does not happen as we made them accessible
			}
		});
		return this;
	}

	private void appendField(String key, Object value) {
		if (value instanceof Map) {
			appendMapEntries((Map<?, ?>) value);
		}
		else {
			append(key, value);
		}
	}

	private void appendMapEntries(Map<?, ?> values) {
		// map is broken down into individual key/value pairs
		values.forEach((key, value) -> {
			if (value instanceof AuditDto.ResponseAttributeValue attributeValue) {
				// contains key and postfix
				append(String.valueOf(key), attributeValue.getValue(), attributeValue.getPostfix(),
						attributeValue.getSource(), attributeValue.getCount());
			}
			else {
				append(String.valueOf(key), value);
			}
		});
	}

	public String build() {
		return output.toString();
	}

	@Override
	public String toString() {
		return output.toString();
	}
}
