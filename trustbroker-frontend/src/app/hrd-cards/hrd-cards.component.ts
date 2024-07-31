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

import { BreakpointObserver, BreakpointState } from '@angular/cdk/layout';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Params } from '@angular/router';

import { environment } from '../../environments/environment';
import { IdpObject } from '../model/idpObject';
import { Theme } from '../model/Theme';
import { ApiService } from '../services/api.service';
import { IdpObjectService } from '../services/idp-object.service';
import { LanguageService } from '../services/language.service';
import { ThemeService } from '../services/theme-service';

@Component({
	selector: 'app-hrd-cards',
	templateUrl: './hrd-cards.component.html',
	styleUrls: ['./hrd-cards.component.scss']
})
export class HrdCardsComponent implements OnInit {
	showHrd = true;
	idpObjects: IdpObject[];
	baseUrl: string = environment.apiUrl;
	authnRequestId: string;
	isButtonSize: boolean;
	clicked: boolean;
	theme: Theme;

	constructor(
		private readonly apiService: ApiService,
		private readonly route: ActivatedRoute,
		private readonly breakpointObserver: BreakpointObserver,
		private readonly idpObjectService: IdpObjectService,
		public readonly languageService: LanguageService,
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
			const issuer = params.issuer;
			if (issuer === undefined) {
				// NOSONAR
				// console.debug('[HrdCardsComponent] No issuer provided');
				this.idpObjects = [];
				return;
			}
			this.apiService.getIdpObjects(issuer).subscribe(value => {
				if (value.length === 1 && !value[0].disabled) {
					this.showHrd = false;
					this.onClickCard(value[0]);
				} else {
					this.idpObjects = value;
					this.idpObjectService.addIdpObjects(value);
				}
			});
		});

		this.breakpointObserver.observe(['(min-width: 768px)']).subscribe((state: BreakpointState) => {
			if (state.matches) {
				this.isButtonSize = false;
			} else {
				this.isButtonSize = true;
			}
		});
	}

	getImageUrl(imageName): string {
		const currentLang = this.languageService.currentLang;
		const newImgName = imageName.replace('{language}', currentLang);

		return `${this.baseUrl}hrd/images/${newImgName}`;
	}

	onClickCard(idpObject): void {
		if (this.clicked || idpObject.disabled) {
			return;
		}
		this.clicked = true;
		this.apiService.selectIDP(this.authnRequestId, idpObject.urn).subscribe({
			next: resp => {
				const location = resp.headers.get('location');
				if (location) {
					// writing the body of the redirect result to the document does not work
					window.location.href = location;
					return;
				}
				window.document.write(resp.body);
				if (document.forms.length > 0) {
					document.forms.item(0).submit();
				} else {
					// not a SAML form, e.g. AccessRequest
					// NOSONAR
					// console.info('[HrdCardsComponent] Do not have a form to submit');
				}
			},
			error: (errorResponse: HttpErrorResponse) => {
				console.error(errorResponse);
			}
		});
	}

	isDisabled(disabled: boolean) {
		if (disabled) {
			return 1;
		}
		return 0;
	}
}
