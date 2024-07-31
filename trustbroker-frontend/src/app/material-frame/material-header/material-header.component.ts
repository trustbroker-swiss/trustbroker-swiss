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

import { Component, EventEmitter, Input, OnInit, Output, ViewChild, ViewEncapsulation } from '@angular/core';
import { ObEColor, ObPopoverDirective } from '@oblique/oblique';

import { Theme } from '../../model/Theme';
import { ApiService } from '../../services/api.service';
import { LanguageService } from '../../services/language.service';
import { ThemeService } from '../../services/theme-service';

@Component({
	selector: 'app-mat-header',
	templateUrl: './material-header.component.html',
	styleUrls: ['./material-header.component.scss'],
	encapsulation: ViewEncapsulation.None
})
export class MaterialHeaderComponent implements OnInit {
	@Input() appName: string;

	@Input() environment: string;

	@Input() theme: Theme = ThemeService.defaultTheme;

	@Input() readonly helpPanelState: EventEmitter<boolean>;

	@Output() readonly helpPanel = new EventEmitter<boolean>();

	@ViewChild(ObPopoverDirective) popover: ObPopoverDirective;

	languageDropdownVisible: boolean;
	helpPanelVisible: boolean;
	readonly languages: string[];

	constructor(public readonly languageService: LanguageService, private readonly apiService: ApiService) {
		this.languages = this.languageService.availableLanguages;
		this.languageDropdownVisible = false;
		this.helpPanelVisible = false;
	}

	ngOnInit(): void {
		if (this.helpPanelState !== null) {
			this.helpPanelState.subscribe({
				next: event => {
					this.helpPanelVisible = event === 'open';
				}
			});
		}
	}

	languageSelectionToggle(): void {
		this.languageDropdownVisible = !this.languageDropdownVisible;
	}

	changeLanguage(lang): void {
		this.languageService.changeLanguage(lang);
		if (this.popover !== null) {
			this.popover.close();
		}
		this.languageDropdownVisible = false;
	}

	toggleHelpPanel(value: boolean): void {
		if (this.theme.hasHelpPanel) {
			this.helpPanel.emit(value);
		} else {
			const helpLink = this.languageService.translate('trustbroker.header.help.link');
			const helpTarget = this.languageService.translate('trustbroker.header.help.target');
			window.open(helpLink, helpTarget);
		}
	}

	bannerColor() {
		switch (this.environment) {
			case 'DEV':
			case 'REF':
				return ObEColor.DEFAULT;
			default:
				return '#fff';
		}
	}

	bannerBgColor() {
		switch (this.environment) {
			case 'LOCAL':
				return ObEColor.SUCCESS;
			case 'DEV':
				return '#ffd700';
			case 'REF':
				return ObEColor.WARNING;
			case 'TEST':
				return ObEColor.PRIMARY;
			case 'ABN':
				return ObEColor.ERROR;
			default:
				return ObEColor.SUCCESS;
		}
	}

	hideBanner() {
		this.environment = '';
	}

	languageSelectionExpanded(): boolean {
		return this.languageDropdownVisible;
	}

	helpExpanded(): boolean {
		return this.helpPanelVisible;
	}

	imageUrl(image: string) {
		return this.apiService.getImageUrl(this.theme, image);
	}
}
