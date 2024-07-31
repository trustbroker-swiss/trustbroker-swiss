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

import java.util.function.Consumer;

import lombok.extern.slf4j.Slf4j;
import org.opensaml.core.xml.XMLObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import swiss.trustbroker.audit.dto.EventType;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;

/**
 * Performs the actual logging. Separate class to allow mocking in tests.
 * <br/>
 * Audit entries emitted as follows:
 * <ul>
 * <li>INFO: RP.AuthnRequest, RP.Response, RP.LogoutRequest</li>
 * <li>DEBUG: CP.AuthnRequest, CP.Response</li>
 * <li>TRACE: AttributeValue marked with FQ name</li>
 * <li>If AuditLoggerDetails=TRACE the full SAML message is attached as a detail field (large).</li>
 * </ul>
 */
@Slf4j
@Component
public class AuditLogger {

	@SuppressWarnings("java:S1312")
	private static final Logger logDetail = LoggerFactory.getLogger(AuditLogger.class.getName() + "Details");

	/**
	 * Audit message and context data to analyze login traffic and record what's needed for compliance.
	 * @param eventType is SAML AuthnRequest or Response
	 * @param inbound means messages coming in (AuthnRequest from RP or Response from CP)
	 * @param message contains the data already mapped via <code>AuditMapper</code> and formatted by <code>AuditLogBuilder</code>
	 */
	public void log(EventType eventType, boolean inbound, String message) {
		logLevel(eventType, inbound).accept(message);
	}

	private static Consumer<String> logLevel(EventType eventType, boolean inbound) {
		return switch (eventType) {
			// in: conversation start, RP authnrequest, CP unknown / out: conversation continue, CP selected
			case AUTHN_REQUEST -> inbound ? log::info : log::debug;
			// in: conversation continue, CP responded / out: conversation done, response to RP
			case RESPONSE -> inbound ? log::debug : log::info;
			// in: conversation continue, CP responded / out: conversation done, response to RP
			case LOGOUT_REQUEST -> log::info;
			case OIDC_LOGOUT -> log::info;
			// in: logout initiated by TB, RP responded / out: logout initiated by RP, response to RP
			case LOGOUT_RESPONSE -> inbound ? log::debug : log::info;
			case RST_REQUEST -> log::debug;
			case RST_RESPONSE -> log::info;
			case OIDC_TOKEN -> log::info; // access_token is not opaque so we log that primarily
			case OIDC_IDTOKEN -> log::debug; // id_token has same content currently so DEBUG
			default -> log::warn;
		};
	}

	public static String getAuditDetail(final XMLObject xmlObject) {
		if (xmlObject != null && isDetailAuditingEnabled()) {
			return OpenSamlUtil.samlObjectToString(xmlObject, true, false);
		}
		return null;
	}

	static boolean isAdditionalAuditingEnabled() {
		return log.isTraceEnabled();
	}

	static boolean isDetailAuditingEnabled() {
		return logDetail.isTraceEnabled();
	}

}
