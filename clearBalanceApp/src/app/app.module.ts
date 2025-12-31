import { HTTP_INTERCEPTORS, HttpClientModule } from '@angular/common/http';
import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { ProfileModule } from './component/profile/profile.module';
import { TokenInterceptor } from './interceptor/token.interceptor';
import { CacheInterceptor } from './interceptor/cache.interceptor';
import { SharedModule } from './component/shared/shared.module';
import { CoreModule } from './core/core.module';
import { AuthModule } from './auth/auth.module';
import { CustomerModule } from './component/customer/customer.module';
import { InvoiceModule } from './component/invoice/invoice.module';
import { HomeModule } from './component/home/home.module';

@NgModule({
  declarations: [
    AppComponent,
  ],
  imports: [
    AppRoutingModule,
    AuthModule,
    BrowserModule,
    BrowserAnimationsModule,
    CustomerModule,
    HttpClientModule,
    SharedModule,
    CoreModule,
    InvoiceModule,
    HomeModule,
    ProfileModule
  ],
  providers: [
    {
      provide: HTTP_INTERCEPTORS,
      useClass: TokenInterceptor,
      multi: true
    },
    {
      provide: HTTP_INTERCEPTORS,
      useClass: CacheInterceptor,
      multi: true
    }
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
