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

package swiss.trustbroker.api.announcements.service;

import java.util.List;
import java.util.Set;

import swiss.trustbroker.api.announcements.dto.Announcement;
import swiss.trustbroker.api.announcements.dto.AnnouncementsRpData;
import swiss.trustbroker.api.relyingparty.dto.RelyingPartyConfig;

/**
 * Announcements can be shown e.g. for operational purposes.
 * <br/>
 * This interface is preliminary and could still change.
 * <br/>
 * An implementation can be configured via Spring @Value binding or by injecting swiss.trustbroker.config.TrustbrokerProperties
 * and using swiss.trustbroker.config.dto.AnnouncementsConfig (${trustbroker.config.announcements}).
 */
public interface AnnouncementService {

	boolean showAnnouncements(AnnouncementsRpData announcementsRpData, String providerName, Set<String> conditions);

	boolean isRpAppAccessible(Announcement announcement);

	List<Announcement> getAnnouncementsForApplication(RelyingPartyConfig relyingPartyConfig,
			AnnouncementsRpData announcementsRpData, String appName);

	public List<Announcement> getGlobalAnnouncements();

}
