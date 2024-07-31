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

package swiss.trustbroker.wstrust.dto;

import lombok.Data;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.soap.wsaddressing.Action;
import org.opensaml.soap.wsaddressing.MessageID;
import org.opensaml.soap.wsaddressing.ReplyTo;
import org.opensaml.soap.wsaddressing.To;
import org.opensaml.soap.wssecurity.Timestamp;

@Data
public class SoapMessageHeader {

	Action action;

	MessageID messageId;

	ReplyTo replyTo;

	To to;

	Timestamp requestTimestamp;

	Assertion assertion;
}

