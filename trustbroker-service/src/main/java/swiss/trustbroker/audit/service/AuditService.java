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

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import swiss.trustbroker.audit.dto.AuditDto;
import swiss.trustbroker.audit.dto.EventType;

@Service
public class AuditService {

	private static final Map<EventType, String> PREFIXES = Map.of(
			EventType.AUTHN_REQUEST, "AuthnRequest: ",
			EventType.RESPONSE, "AuthnResponse: ",
			EventType.LOGOUT_REQUEST, "LogoutRequest: ",
			EventType.LOGOUT_RESPONSE, "LogoutResponse: ",
			EventType.RST_REQUEST, "RstRequest: ",
			EventType.RST_RESPONSE, "RstResponse: "
	);

	private static final String MAPPED_RESPONSE_TYPE = "response";
	private static final String MAPPED_LOGOUT_TYPE = "logout";

	private static final Map<EventType, String> EVENTS = Map.of(
			EventType.AUTHN_REQUEST, "authnrequest",
			EventType.RESPONSE, MAPPED_RESPONSE_TYPE,
			EventType.LOGOUT_REQUEST, MAPPED_LOGOUT_TYPE,
			EventType.LOGOUT_RESPONSE, MAPPED_RESPONSE_TYPE,
			EventType.RST_REQUEST, "rst",
			EventType.RST_RESPONSE, MAPPED_RESPONSE_TYPE,
			EventType.OIDC_TOKEN, "token", // OIDC access_token response
			EventType.OIDC_IDTOKEN, "id_token",
			EventType.OIDC_LOGOUT, MAPPED_LOGOUT_TYPE
	);

	private final AuditLogger logger;

	@Autowired
	public AuditService(AuditLogger logger) {
		this.logger = logger;
	}

	public void logInboundSamlFlow(AuditDto auditDto) {
		var incomingMessage = buildRoutingMessage(auditDto);
		logger.log(auditDto.getEventType(), true, incomingMessage.build());
	}

	public void logOutboundSamlFlow(AuditDto auditDto) {
		var incomingMessage = buildRoutingMessage(auditDto);
		logger.log(auditDto.getEventType(), false, incomingMessage.build());
	}

	private static AuditLogBuilder buildRoutingMessage(AuditDto auditDto) {
		String prefix = PREFIXES.get(auditDto.getEventType());
		var logBuilder = new AuditLogBuilder(prefix);

		logBuilder.append("event", EVENTS.get(auditDto.getEventType()));
		logBuilder.appendDtoFields(auditDto);

		var auditDetail = AuditLogger.getAuditDetail(auditDto.getSamlMessage());
		if (auditDetail != null) {
			logBuilder.append("detail", auditDetail);
		}

		return logBuilder;
	}

}
