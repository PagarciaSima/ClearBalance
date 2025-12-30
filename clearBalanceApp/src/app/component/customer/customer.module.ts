import { NgModule } from '@angular/core';
import { CoreModule } from 'src/app/core/core.module';
import { SharedModule } from 'src/app/shared/shared.module';
import { CustomerDetailComponent } from './customer-detail/customer-detail.component';
import { CustomerRoutingModule } from './customer-routing.module';
import { CustomersComponent } from './customers/customers.component';
import { NewcustomerComponent } from './newcustomer/newcustomer.component';

@NgModule({
  declarations: [
    CustomerDetailComponent,
    NewcustomerComponent,
    CustomersComponent,
  ],
  imports: [
    SharedModule,
    CoreModule,
    CustomerRoutingModule
  ]
})
export class CustomerModule { }
