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

import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Params } from '@angular/router';

import { Theme } from '../model/Theme';
import { ApiService } from '../services/api.service';
import { ThemeService } from '../services/theme-service';

@Component({
	selector: 'app-error-page',
	templateUrl: './error-page.component.html',
	styleUrls: ['./error-page.component.scss']
})
export class ErrorPageComponent implements OnInit {
	titleKey: string;
	textKey: string;
	errorCode: string;
	infoKey: string;
	sessionId: string;
	continueButton: boolean;
	unknown: boolean;
	reloginButton: boolean;
	supportInfo: boolean;
	referenceKey: string;
	reference: string;
	supportContactUrl: string;
	supportInfoText: string;
	supportContactText: string;
	theme: Theme;

	constructor(private readonly route: ActivatedRoute, private readonly themeService: ThemeService, private readonly apiService: ApiService) {
		this.referenceKey = 'trustbroker.error.main.reference';
		this.theme = this.themeService.getTheme();
		this.themeService.subscribe({
			next: theme => {
				this.theme = theme;
			}
		});
	}

	ngOnInit(): void {
		this.route.params.subscribe((params: Params) => {
			let textKey = params.textKey;
			if (!textKey) {
				textKey = 'default';
			}
			if (
				this.parameterInvalid(textKey, '^[0-9A-Za-z]*$') ||
				this.parameterInvalid(params.reference, '^[0-9A-Za-z.-]*$') ||
				this.parameterInvalid(params.sessionId, '^[0-9A-Za-z_-]*$')
			) {
				return;
			}
			this.errorCode = textKey;
			this.titleKey = `trustbroker.error.main.title.${this.errorCode}`;
			this.infoKey = `trustbroker.error.main.info.${this.errorCode}`;
			// default can be overridden via params:
			this.textKey = `trustbroker.error.main.text.${this.errorCode}`;
			this.supportContactUrl = `trustbroker.error.main.support.link.${this.errorCode}`;
			this.supportInfoText = `trustbroker.error.main.support.info.${this.errorCode}`;
			this.supportContactText = `trustbroker.error.main.support.contact.${this.errorCode}`;

			this.reference = params.reference;
			this.sessionId = params.sessionId;
			const buttonStr: string = params.button;
			this.continueButton = buttonStr?.includes('continue');
			this.reloginButton = buttonStr?.includes('relogin');
			this.supportInfo = buttonStr?.includes('support');
		});
	}

	imageUrl(image: string) {
		return this.apiService.getImageUrl(this.theme, image);
	}

	private parameterInvalid(value: string, pattern: string): boolean {
		if (!!value && !value.match(pattern)) {
			console.error('Invalid parameter ', value);
			return true;
		}
		return false;
	}
}
