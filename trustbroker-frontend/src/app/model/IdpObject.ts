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

export interface IdpObject {
	urn: string;
	title: string;
	image: string;
	button: string;
	name: string;
	shortcut: string;
	color: string;
	disabled: boolean;
	order?: number;
}

export interface BannerConfig {
	name: string;
	mainImage?: string;
	secondaryImages?: string[];
	collapseParagraphsOnSmallScreen?: boolean;
	order?: number;
}

export interface IdpObjects {
	tiles?: IdpObject[];
	banners?: BannerConfig[];
}
