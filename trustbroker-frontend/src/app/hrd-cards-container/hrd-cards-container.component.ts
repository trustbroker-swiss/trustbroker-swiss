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

import { ChangeDetectionStrategy, Component } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { ApiService } from '../services/api.service';
import { of, switchMap } from 'rxjs';

@Component({
	selector: 'app-hrd-cards-container',
	templateUrl: './hrd-cards-container.component.html',
	changeDetection: ChangeDetectionStrategy.OnPush
})
export class HrdCardsContainerComponent {
	idpObjects$ = this.route.params.pipe(switchMap(({ issuer, authnRequestId }) => (issuer ? this.apiService.getIdpObjects(issuer, authnRequestId) : of({}))));

	constructor(
		private readonly route: ActivatedRoute,
		private readonly apiService: ApiService
	) {}
}
