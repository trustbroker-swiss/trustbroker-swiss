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

import { HttpErrorResponse } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Params, Router } from '@angular/router';

import { AnnouncementsService } from '../services/announcements.service';
import { AnnouncementResponse } from '../services/announcement-response';
import { ThemeService } from '../services/theme-service';
import { Theme } from '../model/Theme';

@Component({
	selector: 'app-announcements',
	templateUrl: './announcements.component.html',
	styleUrls: ['./announcements.component.scss']
})
export class AnnouncementsComponent implements OnInit {
	showAnnouncements = false;
	announcements: AnnouncementResponse[];
	appVisible: boolean;
	theme: Theme;
	private authnRequestId: string;
	private issuer: string;
	private referer: string;

	constructor(
		private readonly announcementService: AnnouncementsService,
		private readonly route: ActivatedRoute,
		private readonly router: Router,
		private readonly themeService: ThemeService
	) {
		this.theme = this.themeService.getTheme();
		this.themeService.subscribe({
			next: theme => {
				this.theme = theme;
			}
		});
	}

	ngOnInit(): void {
		this.route.params.subscribe((params: Params) => {
			this.authnRequestId = params.authnRequestId;
			this.issuer = params.issuer;
			this.referer = params.referer;
			const navRoute = `home/${this.issuer}/${this.authnRequestId}`;
			this.announcementService.getAnnouncements(this.issuer, this.referer).subscribe({
				next: resp => {
					if (resp == null || resp.length === 0) {
						void this.router.navigate([navRoute]);
					} else {
						this.showAnnouncements = true;
					}
					this.announcements = resp;
					this.appVisible = this.applicationAccessible();
				},
				error: (errorResponse: HttpErrorResponse) => {
					console.error(errorResponse);
					void this.router.navigate([navRoute]);
				}
			});
		});
	}

	continueToApp() {
		const navRoute = `home/${this.issuer}/${this.authnRequestId}`;
		void this.router.navigate([navRoute]);
	}

	applicationAccessible() {
		for (const announcement of this.announcements) {
			if (!announcement.applicationAccessible) {
				return false;
			}
		}
		return true;
	}
}
