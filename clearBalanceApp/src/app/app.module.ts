import { HTTP_INTERCEPTORS, HttpClientModule } from '@angular/common/http';
import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { LoginComponent } from './component/login/login.component';
import { RegisterComponent } from './component/register/register.component';
import { ResetpasswordComponent } from './component/resetpassword/resetpassword.component';
import { VerifyComponent } from './component/verify/verify.component';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { UfoComponent } from './component/ufo/ufo.component';
import { ShootingStarComponent } from './component/shooting-star/shooting-star.component';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { PageNotFoundComponent } from './component/page-not-found/page-not-found.component';
import { CustomerComponent } from './component/customer/customer.component';
import { ProfileComponent } from './component/profile/profile.component';
import { ReportModalComponent } from './component/report-modal/report-modal.component';
import { ReportDetailModalComponent } from './component/report-detail-modal/report-detail-modal.component';
import { HomeComponent } from './component/home/home.component';
import { CustomersComponent } from './component/customers/customers.component';
import { NavbarComponent } from './component/navbar/navbar.component';
import { StatsComponent } from './component/stats/stats.component';
import { FooterComponent } from './component/footer/footer.component';
import { TokenInterceptor } from './interceptor/token.interceptor';
import { PermissionFormatPipe } from './pipes/permission-format.pipe';
import { RoleFormatPipe } from './pipes/role-format.pipe';
import { EventTypeFormatPipe } from './pipes/event-type-format.pipe';
import { PaginationComponent } from './component/pagination/pagination.component';
import { CustomerStatusPipe } from './pipes/customer-status.pipe';
import { CapitalizePipe } from './pipes/capitalize.pipe';

@NgModule({
  declarations: [
    AppComponent,
    LoginComponent,
    RegisterComponent,
    ResetpasswordComponent,
    VerifyComponent,
    UfoComponent,
    ShootingStarComponent,
    PageNotFoundComponent,
    CustomerComponent,
    ProfileComponent,
    HomeComponent,
    CustomersComponent,
    NavbarComponent,
    StatsComponent,
    FooterComponent,
    PermissionFormatPipe,
    RoleFormatPipe,
    EventTypeFormatPipe,
    PaginationComponent,
    ReportModalComponent,
    ReportDetailModalComponent,
    CustomerStatusPipe,
    CapitalizePipe,

  ],
  imports: [
    ReactiveFormsModule,
    AppRoutingModule,
    BrowserModule,
    BrowserAnimationsModule,
    FormsModule,
    HttpClientModule
  ],
  providers: [
    {
      provide: HTTP_INTERCEPTORS,
      useClass: TokenInterceptor,
      multi: true
    }
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
