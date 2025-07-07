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
import { Observable } from 'rxjs';

import { environment } from '../../environments/environment';
import { SsoParticipant } from '../model/SsoParticipant';
import { SsoParticipants } from '../model/SsoParticipants';
import { Theme } from '../model/Theme';
import { ApiService } from '../services/api.service';
import { ThemeService } from '../services/theme-service';

@Component({
	selector: 'app-sso-cards',
	templateUrl: './sso.component.html',
	styleUrls: ['./sso.component.scss']
})
export class SsoComponent implements OnInit {
	ssoParticipants: SsoParticipants[];
	ssoGroupName: string;
	ssoSubject: string;
	baseUrl: string = environment.apiUrl;
	isButtonSize: boolean;
	silentLogout: boolean;
	logoutIssuer: string;
	returnUrl: string;
	clicked: boolean;
	theme: Theme;

	constructor(
		private readonly apiService: ApiService,
		private readonly route: ActivatedRoute,
		private readonly breakpointObserver: BreakpointObserver,
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
			this.setParams(params);
			let participants: Observable<SsoParticipants[]>;
			if (this.silentLogout) {
				participants = this.apiService.logoutSingleActiveGroup(this.logoutIssuer);
			} else {
				participants = this.apiService.getSsoParticipants(this.ssoGroupName);
			}
			// missing subscribe happens in the test mock even though the result is created with rxjs 'of'
			participants.subscribe?.(value => {
				if (this.silentLogout && value.length === 0) {
					this.gotoReturnUrl();
				} else {
					this.setSsoParticipants(value);
				}
			});
		});

		this.breakpointObserver.observe(['(min-width: 768px)']).subscribe((state: BreakpointState) => {
			this.isButtonSize = !state.matches;
		});
	}

	getImageUrl(imageName: string): string {
		// re-use of HRD images in SSO, not too nice, but avoids duplication
		return `${this.baseUrl}hrd/images/${imageName}`;
	}

	onClickCard(ssoGroupName: string, rpId: string, cpId: string, subjectNameId: string): void {
		if (this.clicked) {
			return;
		}
		this.clicked = true;
		// NOSONAR
		// console.debug('[SSOComponent] Selected RP', urn, 'in group', ssoGroupName);
		this.apiService.logoutSsoParticipant(ssoGroupName, rpId, cpId, subjectNameId).subscribe({
			next: resp => {
				const location = resp.headers.get('location');
				if (!location) {
					window.location.reload();
				} else {
					// NOSONAR
					// console.debug('[SSOComponent] Retrieved location', location);
					window.location.href = location;
				}
			},
			error: (errorResponse: HttpErrorResponse) => {
				console.error(errorResponse);
			}
		});
	}

	private setParams(params: Params) {
		this.setReturnUrlIfValid(params['redirect']);
		this.ssoGroupName = params['ssoGroupName'];
		this.ssoSubject = params['ssoSubject'];
		this.logoutIssuer = params['ssuer'];
		this.silentLogout = params['silent'] === 'silent' && this.returnUrl != null && this.logoutIssuer != null;
		// NOSONAR
		// console.debug('[SSOComponent] Extracted parameters:');
		// console.debug('[SSOComponent] ssoGroupName (= param)', this.ssoGroupName);
		// console.debug('[SSOComponent] ssoSubject (= param)', this.ssoSubject);
		// console.debug('[SSOComponent] silentLogout / silent param', this.silentLogout, params.silent);
		// console.debug('[SSOComponent] logoutIssuer (= issuer param)', this.logoutIssuer);
		// console.debug('[SSOComponent] returnUrl / redirect param', this.returnUrl, params.redirect);
	}

	private setReturnUrlIfValid(returnUrl: string) {
		if (!!returnUrl && returnUrl.length > 0 && this.isValidHttpUrl(returnUrl)) {
			this.returnUrl = returnUrl;
		} else {
			this.returnUrl = undefined;
		}
	}

	// allow only successfully parsed URL with http[s] scheme (in particular we must avoid script and data URLs)
	private isValidHttpUrl(returnUrl: string) {
		try {
			const url = new URL(returnUrl);
			return url.protocol === 'http:' || url.protocol === 'https:';
		} catch (ex) {
			console.error('Return URL is not valid', ex, returnUrl);
		}
		return false;
	}

	// as we perform this in the browser, it is not an 'open redirect', we're just changing the location in the browser
	private gotoReturnUrl() {
		window.location.href = this.returnUrl;
	}

	private setSsoParticipants(ssoParticipants: SsoParticipants[]) {
		this.ssoParticipants = Array.from({ length: ssoParticipants.length });
		ssoParticipants.forEach((participant, groupIndex) => {
			const group = new SsoParticipants();
			group.ssoGroupName = participant.ssoGroupName;
			group.ssoSubject = participant.ssoSubject;
			group.ssoEstablishedTime = participant.ssoEstablishedTime;
			group.expirationTime = participant.expirationTime;
			group.participants = Array.from({ length: participant.participants.length });
			participant.participants.forEach((ssoParticipant, partIndex) => {
				const entry = new SsoParticipant();
				entry.rpId = ssoParticipant.rpId;
				entry.cpId = ssoParticipant.cpId;
				entry.name = this.sanitizeName(ssoParticipant.rpId);
				entry.button = ssoParticipant.button;
				entry.image = ssoParticipant.image;
				entry.shortcut = ssoParticipant.shortcut;
				entry.color = ssoParticipant.color;
				group.participants[partIndex] = entry;
			});
			this.ssoParticipants[groupIndex] = group;
		});
	}

	private sanitizeName(id: string) {
		return id.replace(/^.*:/g, '');
	}
}
