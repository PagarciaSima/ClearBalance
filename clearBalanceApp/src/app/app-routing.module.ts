import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { LoginComponent } from './component/login/login.component';
import { RegisterComponent } from './component/register/register.component';
import { ResetpasswordComponent } from './component/resetpassword/resetpassword.component';
import { VerifyComponent } from './component/verify/verify.component';
import { PageNotFoundComponent } from './component/page-not-found/page-not-found.component';
import { CustomerComponent } from './component/customer/customer.component';
import { ProfileComponent } from './component/profile/profile.component';
import { CustomersComponent } from './component/customers/customers.component';
import { HomeComponent } from './component/home/home.component';
import { authenticationGuard } from './guards/authentication.guard';
import { NewcustomerComponent } from './component/newcustomer/newcustomer.component';
import { NewinvoiceComponent } from './component/newinvoice/newinvoice.component';
import { InvoicesComponent } from './component/invoices/invoices.component';
import { InvoiceComponent } from './component/invoice/invoice.component';

/**
 *  set up the routes for the application
 */
const routes: Routes = [
  { path: 'login', component: LoginComponent },
  { path: 'register', component: RegisterComponent },
  { path: 'resetpassword', component: ResetpasswordComponent },
  { path: 'user/verify/account/:key', component: VerifyComponent },
  { path: 'user/verify/password/:key', component: VerifyComponent },
  { path: 'customers', component: CustomersComponent, canActivate: [authenticationGuard] },
  { path: 'profile', component: ProfileComponent, canActivate: [authenticationGuard] },
  { path: 'customers/new', component: NewcustomerComponent, canActivate: [authenticationGuard] },
  { path: 'invoices/new', component: NewinvoiceComponent, canActivate: [authenticationGuard] },
  { path: 'invoices', component: InvoicesComponent, canActivate: [authenticationGuard] },
  { path: 'customer/:id', component: CustomerComponent, canActivate: [authenticationGuard] },
  { path: 'invoices/:id/:invoiceNumber', component: InvoiceComponent, canActivate: [authenticationGuard] },
  { path: '', component: HomeComponent, canActivate: [authenticationGuard], pathMatch: 'full' },
  { path: '**', component: PageNotFoundComponent},
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
