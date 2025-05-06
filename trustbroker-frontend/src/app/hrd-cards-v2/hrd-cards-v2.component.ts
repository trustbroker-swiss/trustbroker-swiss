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

import { ChangeDetectionStrategy, Component, DestroyRef, effect, input } from '@angular/core';
import { IdpObject, IdpObjects } from '../model/IdpObject';
import { environment } from '../../environments/environment';
import { ThemeService } from '../services/theme-service';
import { ActivatedRoute, Router } from '@angular/router';
import { ApiService } from '../services/api.service';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { switchMap } from 'rxjs';
import { IdpObjectService } from '../services/idp-object.service';

@Component({
	selector: 'app-hrd-cards-v2',
	templateUrl: './hrd-cards-v2.component.html',
	styleUrl: './hrd-cards-v2.component.scss',
	changeDetection: ChangeDetectionStrategy.OnPush
})
export class HrdCardsV2Component {
	baseUrl: string = environment.apiUrl;

	idpObjects = input.required<IdpObjects>();
	theme$ = this.themeService.theme$;

	constructor(
		private readonly route: ActivatedRoute,
		private readonly router: Router,
		private readonly apiService: ApiService,
		protected readonly themeService: ThemeService,
		private readonly destroyRef: DestroyRef,
		private readonly idpObjectService: IdpObjectService
	) {
		effect(() => {
			if (this.idpObjects().tiles?.length === 1 && !this.idpObjects().tiles[0].disabled) {
				this.onCardClick(this.idpObjects().tiles[0]);
			} else if (this.idpObjects().tiles?.length > 1) {
				this.idpObjectService.addIdpObjects(this.idpObjects().tiles);
			}
		});
	}

	public onCardClick(idpObject: IdpObject) {
		this.route.params
			.pipe(
				switchMap(params => this.apiService.selectIdp(params.authnRequestId, idpObject.urn)),
				takeUntilDestroyed(this.destroyRef)
			)
			.subscribe({
				next: response => {
					const location = response.headers.get('location');
					if (location) {
						// writing the body of the redirect result to the document does not work
						window.location.href = location;
						return;
					}
					// document.write for error page does not work here
					const url = response.url.replace(/^.*(\/failure\/.*$)/, '$1');
					if (url !== response.url) {
						void this.router.navigate([url]);
						return;
					}
					window.document.write(response.body);
					if (document.forms.length > 0) {
						document.forms.item(0).submit();
					} else {
						// not a SAML form, e.g. AccessRequest
						// NOSONAR
						// console.info('[HrdCardsComponent] Do not have a form to submit');
					}
				},
				error: errorResponse => {
					console.error('an error occured', errorResponse);
				}
			});
	}
}
