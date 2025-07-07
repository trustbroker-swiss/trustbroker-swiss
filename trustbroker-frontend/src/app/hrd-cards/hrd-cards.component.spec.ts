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

import { HttpClient, HttpClientModule } from '@angular/common/http';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { RouterTestingModule } from '@angular/router/testing';
import { TranslateLoader, TranslateModule } from '@ngx-translate/core';
import { of } from 'rxjs';
import { mock, when } from 'ts-mockito';

import { TranslationService } from '../app.module';
import { HrdCardsComponent } from './hrd-cards.component';
import { ApiService } from '../services/api.service';
import { SafeMarkupPipe } from '../pipes/safe-markup.pipe';
import { ComponentRef } from '@angular/core';
import { LanguageService } from '../services/language.service';
import { ThemeService } from '../services/theme-service';

describe('HrdCardsComponent', () => {
	let component: HrdCardsComponent;
	let componentRef: ComponentRef<HrdCardsComponent>;
	let fixture: ComponentFixture<HrdCardsComponent>;
	let mockApiService: ApiService;

	beforeEach(async () => {
		await TestBed.configureTestingModule({
			declarations: [HrdCardsComponent, SafeMarkupPipe],
			imports: [
				HttpClientModule,
				RouterTestingModule,
				TranslateModule.forRoot({
					loader: {
						provide: TranslateLoader,
						useClass: TranslationService,
						deps: [HttpClient]
					}
				})
			]
		}).compileComponents();
	});

	beforeEach(() => {
		// mock services
		mockApiService = mock(ApiService);
		when(mockApiService.getConfiguration()).thenReturn(of());
		const mockLanguageService = mock(LanguageService);
		const mockThemeService = mock(ThemeService);
		TestBed.configureTestingModule({
			providers: [
				{ provide: ApiService, useValue: mockApiService },
				{ provide: LanguageService, useValue: mockLanguageService },
				{ provide: ThemeService, useValue: mockThemeService }
			]
		});

		fixture = TestBed.createComponent(HrdCardsComponent);
		component = fixture.componentInstance;
		componentRef = fixture.componentRef;
		componentRef.setInput('idpObjects', []);
		fixture.detectChanges();
	});

	it('should create', () => {
		expect(component).toBeTruthy();
	});
});
