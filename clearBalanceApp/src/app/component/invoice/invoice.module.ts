import { NgModule } from '@angular/core';
import { CoreModule } from 'src/app/core/core.module';
import { SharedModule } from '../shared/shared.module';
import { InvoiceDetailComponent } from './invoice-detail/invoice.component';
import { InvoiceRoutingModule } from './invoice-routing.module';
import { InvoicesComponent } from './invoices/invoices.component';
import { NewinvoiceComponent } from './newinvoice/newinvoice.component';

@NgModule({
  declarations: [
    InvoicesComponent,
    InvoiceDetailComponent,
    NewinvoiceComponent,
  ],
  imports: [
    CoreModule,
    InvoiceRoutingModule,
    SharedModule,
  ]
})
export class InvoiceModule { }
