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

import { Pipe, PipeTransform, SecurityContext } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

@Pipe({ name: 'safeLinebreaks' })
export class SafeLinebreaksPipe implements PipeTransform {
	constructor(private readonly sanitizer: DomSanitizer) {}

	transform(text: string): SafeHtml {
		// convert supported linebreaks to known value to deal with only a single encoded value later
		text = text.replace(/(?:\r\n|\r|\n|<br\s*\/?>)/g, '\n');
		text = this.sanitizer.sanitize(SecurityContext.HTML, text);
		// replace sanitized line break with HTML line break
		text = text.replace(/&#10;/g, '<br>');
		return this.sanitizer.bypassSecurityTrustHtml(text); // NOSONAR typescript:S6268 - unknown tags are sanitized above
	}
}
