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

import { LayoutModule } from '@angular/cdk/layout';
import { NgModule } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatExpansionModule } from '@angular/material/expansion';
import { MatGridListModule } from '@angular/material/grid-list';
import { MatIconModule, MatIconRegistry } from '@angular/material/icon';
import { MatMenuModule } from '@angular/material/menu';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSidenavModule } from '@angular/material/sidenav';
import { BrowserModule } from '@angular/platform-browser';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { RouterModule } from '@angular/router';
import { HTTP_INTERCEPTORS, HttpClient, HttpClientModule } from '@angular/common/http';
import { StoreRouterConnectingModule } from '@ngrx/router-store';
import { StoreModule } from '@ngrx/store';
import { MissingTranslationHandler, MissingTranslationHandlerParams, TranslateLoader, TranslateModule } from '@ngx-translate/core';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { ObAlertModule, ObIconModule, ObMasterLayoutConfig, ObMasterLayoutModule, ObPopoverModule } from '@oblique/oblique';

import { AccessRequestComponent } from './access-request/access-request.component';
import { AnnouncementComponent } from './announcements/announcement/announcement.component';
import { AnnouncementsComponent } from './announcements/announcements.component';
import { AppComponent } from './app.component';
import { routes } from './app-routing.module';
import { BackdropComponent } from './backdrop/backdrop.component';
import { DeviceInfoComponent } from './device-info/device-info.component';
import { environment } from '../environments/environment';
import { ErrorBoxComponent } from './error-page/error-box/error-box.component';
import { ErrorPageComponent } from './error-page/error-page.component';
import { HelpPanelComponent } from './help-panel/help-panel.component';
import { DisabledCardComponent } from './hrd-cards/disabled-card/disabled-card.component';
import { HrdCardsComponent } from './hrd-cards/hrd-cards.component';
import { SmallCardComponent } from './hrd-cards/small-card/small-card.component';
import { MasterLayoutConfig } from './material-frame/config/master-layout-config';
import { MaterialFooterComponent } from './material-frame/material-footer/material-footer.component';
import { MaterialFrameComponent } from './material-frame/material-frame.component';
import { MaterialHeaderComponent } from './material-frame/material-header/material-header.component';
import { EnvironmentDisplayPipe } from './pipes/environment-display.pipe';
import { LanguageDisplayPipe } from './pipes/language-display.pipe';
import { NativeLanguageDisplayPipe } from './pipes/native-language-display.pipe';
import { SafeMarkupPipe } from './pipes/safe-markup.pipe';
import { ProfileSelectionCardComponent } from './profile-selection/profile-selection-card/profile-selection-card.component';
import { ProfileSelectionComponent } from './profile-selection/profile-selection.component';
import { CustomHttpInterceptor } from './services/custom-http-interceptor.service';
import { DeviceInfoService } from './services/deviceinfo.service';
import { LanguageService } from './services/language.service';
import { ThemeService } from './services/theme-service';
import { SsoComponent } from './sso/sso.component';
import { ThemeSelectorComponent } from './theme-selector/theme-selector';

export class TranslationService implements TranslateLoader {
	private readonly baseUrl = environment.apiUrl;

	constructor(private readonly http: HttpClient) {}

	getTranslation(lang: string): Observable<unknown> {
		return this.http.get(`${this.baseUrl}hrd/translations/${lang}`).pipe(
			map((response: JSON) => {
				return response;
			})
		);
	}
}

export class MissingTranslationHelper implements MissingTranslationHandler {
	handle(params: MissingTranslationHandlerParams): string {
		if (params.interpolateParams) {
			// eslint workaround: as it is an Object we cannot use dot-notation
			const value = 'Default';
			return params.interpolateParams[value] || params.key;
		}
		return params.key;
	}
}

@NgModule({
	declarations: [
		AppComponent,
		HrdCardsComponent,
		SsoComponent,
		MaterialFooterComponent,
		MaterialFrameComponent,
		MaterialHeaderComponent,
		NativeLanguageDisplayPipe,
		LanguageDisplayPipe,
		EnvironmentDisplayPipe,
		SafeMarkupPipe,
		DeviceInfoComponent,
		ErrorBoxComponent,
		ErrorPageComponent,
		HelpPanelComponent,
		ProfileSelectionComponent,
		SmallCardComponent,
		AnnouncementsComponent,
		AnnouncementComponent,
		AccessRequestComponent,
		DisabledCardComponent,
		ProfileSelectionCardComponent,
		BackdropComponent,
		ThemeSelectorComponent
	],
	imports: [
		BrowserModule,
		BrowserAnimationsModule,
		HttpClientModule,
		MatCardModule,
		MatGridListModule,
		MatMenuModule,
		MatIconModule,
		MatButtonModule,
		MatProgressSpinnerModule,
		LayoutModule,
		TranslateModule.forRoot({
			missingTranslationHandler: { provide: MissingTranslationHandler, useClass: MissingTranslationHelper },
			loader: {
				provide: TranslateLoader,
				useClass: TranslationService,
				deps: [HttpClient]
			}
		}),
		ObMasterLayoutModule,
		ObAlertModule,
		ObIconModule.forRoot(),
		StoreRouterConnectingModule.forRoot(),
		StoreModule.forRoot({}, {}),
		RouterModule.forRoot(routes),
		ObPopoverModule,
		MatSidenavModule,
		MatCheckboxModule,
		FormsModule,
		MatExpansionModule
	],
	providers: [
		LanguageService,
		ThemeService,
		DeviceInfoService,
		{ provide: HTTP_INTERCEPTORS, useClass: CustomHttpInterceptor, multi: true },
		{ provide: ObMasterLayoutConfig, useClass: MasterLayoutConfig }
	],
	bootstrap: [AppComponent]
})
export class AppModule {
	constructor(iconRegistry: MatIconRegistry) {
		// Font Awesome as default
		iconRegistry.setDefaultFontSetClass('fas');
	}
}
