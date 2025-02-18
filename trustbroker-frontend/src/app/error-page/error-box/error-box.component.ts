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
import { ApiService } from '../../services/api.service';
import { Theme } from '../../model/Theme';
import { ThemeService } from '../../services/theme-service';
import { SupportInfo } from '../../model/SupportInfo';
import { HttpErrorResponse } from '@angular/common/http';
import { LanguageService } from '../../services/language.service';

@Component({
	selector: 'app-error-box',
	templateUrl: './error-box.component.html',
	styleUrls: ['./error-box.component.scss']
})
export class ErrorBoxComponent implements OnInit {
	@Input()
	titleKey: string;

	@Input()
	textKey: string;

	@Input()
	errorCode: string;

	@Input()
	infoKey: string;

	@Input()
	referenceKey: string;

	@Input()
	reference: string;

	@Input()
	sessionId: string;

	@Input()
	continueButton: boolean;

	@Input()
	reloginButton: boolean;

	@Input()
	supportInfo: boolean;

	@Input()
	supportInfoText: string;

	@Input()
	supportContactText: string;

	@Input()
	supportContactUrl: string;

	@Input()
	theme: Theme = ThemeService.defaultTheme;

	supportInfoData: SupportInfo;

	showSupportInfoText: boolean;

	showSupportContactText: boolean;

	constructor(
		private readonly apiService: ApiService,
		private readonly languageService: LanguageService
	) {}

	continueFlow(): void {
		this.apiService.continueResponseToRp(this.sessionId);
	}

	relogin(): void {
		this.apiService.relogin(this.sessionId);
	}

	ngOnInit(): void {
		this.showSupportInfoText = false;
		this.showSupportContactText = false;
		this.setSupportInfoFlags(this.supportInfoText, this.supportContactText);

		if (this.supportInfo) {
			this.apiService.fetchSupportInfo(this.errorCode, this.sessionId).subscribe({
				next: resp => {
					this.supportInfoData = resp;
				},
				error: (errorResponse: HttpErrorResponse) => {
					console.error(errorResponse);
					this.supportInfo = false;
				}
			});
		}
	}

	setSupportInfoFlags(supportInfoText: string, supportContactText: string) {
		if (supportInfoText == null) {
			return;
		}
		this.languageService.langChange$.subscribe(() => {
			let translated = this.languageService.translate(supportInfoText);
			this.showSupportInfoText = translated !== supportInfoText;
			translated = this.languageService.translate(supportContactText);
			this.showSupportContactText = translated !== supportContactText;
		});
	}
}
