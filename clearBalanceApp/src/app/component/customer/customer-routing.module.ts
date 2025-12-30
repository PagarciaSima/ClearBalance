import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { authenticationGuard } from 'src/app/guards/authentication.guard';
import { CustomerDetailComponent } from './customer-detail/customer-detail.component';
import { CustomersComponent } from './customers/customers.component';
import { NewcustomerComponent } from './newcustomer/newcustomer.component';

const routes: Routes = [
  { path: 'customers', component: CustomersComponent, canActivate: [authenticationGuard] },
  { path: 'customers/new', component: NewcustomerComponent, canActivate: [authenticationGuard] },
  { path: 'customer/:id', component: CustomerDetailComponent, canActivate: [authenticationGuard] },
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class CustomerRoutingModule { }
