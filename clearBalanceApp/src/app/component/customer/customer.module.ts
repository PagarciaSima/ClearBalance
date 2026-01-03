import { NgModule } from '@angular/core';
import { SharedModule } from 'src/app/component/shared/shared.module';
import { CoreModule } from 'src/app/core/core.module';
import { CustomerDetailComponent } from './customer-detail/customer-detail.component';
import { CustomerRoutingModule } from './customer-routing.module';
import { CustomersComponent } from './customers/customers.component';
import { NewcustomerComponent } from './newcustomer/newcustomer.component';
import { CustomersMapComponent } from './customers-map/customers-map.component';

@NgModule({
  declarations: [
    CustomersComponent,
    CustomerDetailComponent,
    NewcustomerComponent,
    CustomersMapComponent,
  ],
  imports: [
    CoreModule,
    CustomerRoutingModule,
    SharedModule,
  ]
})
export class CustomerModule { }
