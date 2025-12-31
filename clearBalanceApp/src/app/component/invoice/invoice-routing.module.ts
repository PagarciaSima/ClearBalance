import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { authenticationGuard } from 'src/app/guards/authentication.guard';
import { InvoiceDetailComponent } from './invoice-detail/invoice.component';
import { InvoicesComponent } from './invoices/invoices.component';
import { NewinvoiceComponent } from './newinvoice/newinvoice.component';

const routes: Routes = [
  { path: '', component: InvoicesComponent, canActivate: [authenticationGuard] },
  { path: 'new', component: NewinvoiceComponent, canActivate: [authenticationGuard] },
  { path: ':id/:invoiceNumber', component: InvoiceDetailComponent, canActivate: [authenticationGuard] },
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class InvoiceRoutingModule { }
