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

import { Component, EventEmitter, Input, Output } from '@angular/core';

@Component({
	selector: 'app-profile-selection-card',
	templateUrl: './profile-selection-card.component.html',
	styleUrls: ['./profile-selection-card.component.scss']
})
export class ProfileSelectionCardComponent {
	showButton = false;
	@Input() id: string;
	@Input() profileName: string;
	@Input() organization: string;
	@Input() applications: string;

	@Output() readonly cardClick = new EventEmitter<string>();

	onClick(id: string) {
		this.cardClick.emit(id);
	}
}
