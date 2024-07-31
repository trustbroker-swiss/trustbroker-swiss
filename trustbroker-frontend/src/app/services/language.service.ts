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

import { DOCUMENT, registerLocaleData } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import localeDe from '@angular/common/locales/de';
import localeFr from '@angular/common/locales/fr';
import localeIt from '@angular/common/locales/it';
import localeEn from '@angular/common/locales/en';
import { Inject, Injectable } from '@angular/core';
import { LangChangeEvent, TranslateService } from '@ngx-translate/core';
import { CookieService } from 'ngx-cookie-service';
import { BehaviorSubject, Connectable, Observable, connectable } from 'rxjs';
import { map, startWith } from 'rxjs/operators';

import { ApiService } from './api.service';
import { CookieConfiguration } from '../model/CookieConfiguration';
import { Constant } from '../shared/constants';

@Injectable({ providedIn: 'root' })
export class LanguageService {
	private langChangeWithTechnicalLang$: Connectable<string>;

	private languageCookie: CookieConfiguration;

	private defaultCookieParameters: boolean;

	get langChangeWithTechnicalLang(): Observable<string> {
		return this.langChangeWithTechnicalLang$;
	}

	get langChange$(): Observable<string> {
		return this.langChangeWithTechnicalLang$.pipe(map(lang => this.getLangOrDefaultIfTechnical(lang)));
	}

	get currentLang(): string {
		return this.getLangOrDefaultIfTechnical(this.translateService.currentLang);
	}

	get availableLanguages(): string[] {
		return Constant.LanguageCodes;
	}

	constructor(
		private readonly cookieService: CookieService,
		private readonly apiService: ApiService,
		private readonly translateService: TranslateService,
		@Inject(DOCUMENT) private readonly document: Document
	) {
		this.languageCookie = new CookieConfiguration();
		this.languageCookie.name = 'LANG';
		this.defaultCookieParameters = true;
		this.loadConfig();
		this.initializeLanguageSettings();
	}

	changeLanguage(language: string): void {
		this.translateService.use(language);
		this.updateLanguageCookie(language);
	}

	// call only in langChange$.subscribe or when initialization of language resources is guaranteed by other means
	translate(key: string): string {
		return this.translateService.instant(key);
	}

	private initializeLanguageSettings(): void {
		this.registerLocales();
		this.initTranslationService();

		this.setLanguage();

		this.translateService.onLangChange.subscribe((event: LangChangeEvent) => {
			const lang = event.lang;
			// NOSONAR
			// console.debug('[LanguageService] Language change detected. New language: ', lang);
			this.document.documentElement.lang = lang;
			this.document.documentElement.setAttribute('xml:lang', lang);
			// keep cookie in sync with language (ObLanguageService is also using local storage)
			this.updateLanguageCookie(lang);
		});

		this.langChangeWithTechnicalLang$ = connectable(
			this.translateService.onLangChange.pipe(
				map(langChange => langChange.lang),
				startWith(this.translateService.currentLang)
			),
			{ connector: () => new BehaviorSubject(this.translateService.currentLang) }
		);
		this.langChangeWithTechnicalLang$.connect();
	}

	private loadConfig() {
		this.apiService.fetchConfiguration()?.subscribe?.({
			next: configuration => {
				const languageCookie: CookieConfiguration = configuration.languageCookie;
				if (languageCookie?.name == null) {
					// NOSONAR
					// console.debug('[LanguageService] Keeping default language cookie', this.languageCookie.name);
					return;
				}
				this.languageCookie = languageCookie;
				this.defaultCookieParameters = false;
				// NOSONAR
				// console.debug('[LanguageService] Server sent language cookie parameters ', this.languageCookie.name);
				this.setLanguage();
			},
			error: (errorResponse: HttpErrorResponse) => {
				console.error(errorResponse);
			}
		});
	}

	private initTranslationService(): void {
		const defaultLanguageCode = this.getBrowserLanguageOrDefault();

		this.translateService.setDefaultLang(defaultLanguageCode);
		this.translateService.addLangs(this.availableLanguages);

		// NOSONAR
		// console.debug(`[LanguageService] TranslateService init: languages ${this.translateService.getLangs()}, default: ${this.translateService.currentLang}`);
	}

	private getLangOrDefaultIfTechnical(lang: string): string {
		return lang;
	}

	private isValidLanguage(lang: string): boolean {
		return this.availableLanguages.includes(lang);
	}

	private setLanguage(): void {
		let languageToSelect: string;
		const languageFromCookie: string = this.cookieService.get(this.languageCookie.name);

		if (languageFromCookie && this.isValidLanguage(languageFromCookie)) {
			// NOSONAR
			// console.debug('[LanguageService] Current language setting found in cookie: ', languageFromCookie);
			languageToSelect = languageFromCookie;
		} else {
			// NOSONAR
			// console.debug('[LanguageService] Current language setting not found in cookie, setting default.');
			languageToSelect = this.translateService.defaultLang;
			// NOSONAR
			// console.debug('[LanguageService] Browser preferences -> Preferred languages: ', languageToSelect);
			// console.debug('[LanguageService] Selected language from browser preferences: ', languageToSelect);

			this.updateLanguageCookie(languageToSelect);
		}

		this.translateService.use(languageToSelect);
	}

	private getBrowserLanguageOrDefault(): string {
		const browserLang = this.translateService.getBrowserLang();
		return this.isValidLanguage(browserLang) ? browserLang : Constant.DefaultLanguageCode.toString();
	}

	private updateLanguageCookie(language: string): void {
		if (this.defaultCookieParameters) {
			// NOSONAR
			// console.debug('[LanguageService] Skip setting cookie based on default parameters');
			return;
		}
		// NOSONAR
		// console.debug('[LanguageService] Setting language cookie:', this.languageCookie.name, '=', language, 'on path', this.languageCookie.path, 'and domain', this.languageCookie.domain);
		this.cookieService.set(
			this.languageCookie.name,
			language,
			this.languageCookie.maxAge,
			this.languageCookie.path,
			this.languageCookie.domain,
			this.languageCookie.secure,
			this.languageCookie.sameSite
		);
	}

	private registerLocales(): void {
		registerLocaleData(localeDe);
		registerLocaleData(localeFr);
		registerLocaleData(localeIt);
		registerLocaleData(localeEn);
	}
}