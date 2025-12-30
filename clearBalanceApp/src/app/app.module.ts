import { HTTP_INTERCEPTORS, HttpClientModule } from '@angular/common/http';
import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { ShootingStarComponent } from './component/shooting-star/shooting-star.component';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { PageNotFoundComponent } from './component/page-not-found/page-not-found.component';
import { ProfileComponent } from './component/profile/profile.component';
import { ReportModalComponent } from './component/report-modal/report-modal.component';
import { ReportDetailModalComponent } from './component/report-detail-modal/report-detail-modal.component';
import { HomeComponent } from './component/home/home.component';
import { NavbarComponent } from './component/navbar/navbar.component';
import { StatsComponent } from './component/stats/stats.component';
import { FooterComponent } from './component/footer/footer.component';
import { TokenInterceptor } from './interceptor/token.interceptor';
import { PermissionFormatPipe } from './pipes/permission-format.pipe';
import { RoleFormatPipe } from './pipes/role-format.pipe';
import { EventTypeFormatPipe } from './pipes/event-type-format.pipe';
import { NewinvoiceComponent } from './component/newinvoice/newinvoice.component';
import { InvoicesComponent } from './component/invoices/invoices.component';
import { InvoiceComponent } from './component/invoice/invoice.component';
import { CacheInterceptor } from './interceptor/cache.interceptor';
import { SharedModule } from './shared/shared.module';
import { CoreModule } from './core/core.module';
import { AuthModule } from './auth/auth.module';
import { CustomerModule } from './component/customer/customer.module';

@NgModule({
  declarations: [
    AppComponent,
    ShootingStarComponent,
    PageNotFoundComponent,
    ProfileComponent,
    HomeComponent,
    NavbarComponent,
    StatsComponent,
    FooterComponent,
    PermissionFormatPipe,
    RoleFormatPipe,
    EventTypeFormatPipe,
    ReportModalComponent,
    ReportDetailModalComponent,
    NewinvoiceComponent,
    InvoicesComponent,
    InvoiceComponent,
  ],
  imports: [
    AppRoutingModule,
    AuthModule,
    BrowserModule,
    BrowserAnimationsModule,
    CustomerModule,
    HttpClientModule,
    SharedModule,
    CoreModule
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
