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

import { Component, Input, OnInit } from '@angular/core';
import { TranslateService } from '@ngx-translate/core';

import { AlertType } from './AlertType';
import { Theme } from '../../model/Theme';
import { InternationalText } from '../../services/international-text';
import { LanguageService } from '../../services/language.service';
import { ThemeService } from '../../services/theme-service';

@Component({
	selector: 'app-announcement',
	templateUrl: './announcement.component.html',
	styleUrls: ['./announcement.component.scss']
})
export class AnnouncementComponent implements OnInit {
	@Input()
	announcementType: string;

	@Input()
	announcementTitle: InternationalText;

	@Input()
	announcementMessage: InternationalText;

	@Input()
	announcementUrl: InternationalText;

	@Input()
	announcementPhoneNumber: string;

	@Input()
	announcementEmailAddress: string;

	@Input()
	theme: Theme = ThemeService.defaultTheme;

	title: string;
	message: string;
	alertType: string;
	contactUrl: string;

	constructor(
		public readonly languageService: LanguageService,
		private readonly translateService: TranslateService
	) {}

	ngOnInit(): void {
		const currentLang = this.languageService.currentLang;
		this.updateText(currentLang);
		this.translateService.onLangChange.subscribe(event => this.updateText(event.lang));
		this.setAlertType();
	}

	// Low amount of announcements/application
	updateText(currentLang: string) {
		this.title = this.announcementTitle[currentLang];
		this.message = this.announcementMessage[currentLang];
		if (this.announcementUrl != null) {
			this.contactUrl = this.announcementUrl[currentLang];
		}
	}

	setAlertType() {
		if (this.announcementType === 'MAINTENANCE') {
			this.alertType = AlertType.warning;
		} else if (this.announcementType === 'INCIDENT') {
			this.alertType = AlertType.error;
		} else {
			this.alertType = AlertType.info;
		}
	}
}
