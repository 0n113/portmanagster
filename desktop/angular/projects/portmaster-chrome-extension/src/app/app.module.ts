import { OverlayModule } from '@angular/cdk/overlay';
import { HTTP_INTERCEPTORS, provideHttpClient, withInterceptorsFromDi } from '@angular/common/http';
import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { PortmasterAPIModule } from '@safing/portmaster-api';
import { TabModule } from '@safing/ui';
import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { ExtDomainListComponent } from './domain-list';
import { ExtHeaderComponent } from './header';
import { AuthIntercepter as AuthInterceptor } from './interceptor';
import { WelcomeModule } from './welcome';


@NgModule({ declarations: [
        AppComponent,
        ExtDomainListComponent,
        ExtHeaderComponent,
    ],
    bootstrap: [AppComponent], imports: [BrowserModule,
        AppRoutingModule,
        PortmasterAPIModule.forRoot(),
        TabModule,
        WelcomeModule,
        OverlayModule], providers: [
        {
            provide: HTTP_INTERCEPTORS,
            multi: true,
            useClass: AuthInterceptor,
        },
        provideHttpClient(withInterceptorsFromDi())
    ] })
export class AppModule { }
