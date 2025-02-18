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

export class Theme {
	constructor(
		readonly name: string,
		readonly hasHeader: boolean,
		readonly hasFooter: boolean,
		readonly hasBackdrop: boolean,
		readonly hasThemeSelector: boolean,
		readonly hasLanguageSelector: boolean,
		readonly fullLanguageName: boolean,
		readonly hasHelp: boolean,
		readonly hasHelpPanel: boolean,
		readonly helpTabindex: number
	) {}
}
