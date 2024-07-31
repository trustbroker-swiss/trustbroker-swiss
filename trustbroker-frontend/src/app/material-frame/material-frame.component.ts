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

import { Component, EventEmitter, Input, ViewChild, ViewEncapsulation } from '@angular/core';
import { Observable } from 'rxjs';

import { Theme } from '../model/Theme';
import { ThemeService } from '../services/theme-service';

@Component({
	selector: 'app-mat-frame',
	templateUrl: './material-frame.component.html',
	styleUrls: ['./material-frame.component.scss'],
	encapsulation: ViewEncapsulation.None
})
export class MaterialFrameComponent {
	opened: boolean;
	@Input() showTopNav: boolean;
	@Input() showMyaccount = true;
	@Input() showOnlyLogout: boolean;
	@Input() appName = 'TB';
	@Input() detailedFooter = true;
	@Input() theme: Theme = ThemeService.defaultTheme;

	@ViewChild('sidenav') sidenav;

	readonly helpPanel = new EventEmitter<boolean>();

	version: Observable<string>;
	currentYear: Observable<number>;
	// legalFrameworkAddresses$: Observable<InternationalText>;
	envPrefix = '';

	toggleHelpPanel(): void {
		if (this.theme.hasHelpPanel) {
			this.sidenav.toggle().then(result => this.helpPanel.emit(result));
		}
	}

	closeHelpPanel(): void {
		if (this.theme.hasHelpPanel) {
			this.sidenav.close().then(result => this.helpPanel.emit(result));
		}
	}
}
