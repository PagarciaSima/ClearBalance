import { Component } from '@angular/core';
import { ActivatedRoute, ParamMap } from '@angular/router';
import { BehaviorSubject, catchError, map, of, startWith, switchMap } from 'rxjs';
import { Observable } from 'rxjs/internal/Observable';
import { slideBlur } from 'src/app/animations/animations';
import { DataState } from 'src/app/enum/datastate.enum';
import { Customer } from 'src/app/interface/customer';
import { CustomHttpResponse } from 'src/app/interface/customhttpresponse';
import { Invoice } from 'src/app/interface/invoice';
import { State } from 'src/app/interface/state';
import { User } from 'src/app/interface/user';
import { CustomerService } from 'src/app/service/customer.service';
import { TooltipService } from 'src/app/service/tooltip.service';

const INVOICE_ID = 'id';

@Component({
  selector: 'app-invoice',
  templateUrl: './invoice.component.html',
  styleUrls: ['./invoice.component.css'],
  animations: [ slideBlur]
})
export class InvoiceComponent {
  invoiceState$!: Observable<State<CustomHttpResponse<{ user: User; invoice: Invoice; customer: Customer }>>>;
  private dataSubject = new BehaviorSubject<CustomHttpResponse<{ user: User; invoice: Invoice; customer: Customer }> | null>(null);
  private isLoadingSubject = new BehaviorSubject<boolean>(false);
  isLoading$ = this.isLoadingSubject.asObservable();
  readonly DataState = DataState;

  constructor(
    private activatedRoute: ActivatedRoute,
    private customerService: CustomerService,
    private tooltipService: TooltipService
  ) { }

  /**
   * Angular lifecycle hook that is called after component initialization.
   * Sets up the invoice state observable and initializes tooltips.
   */
  ngOnInit(): void {
    this.tooltipService.initialize();
    this.getCurrentInvoice();
  }

  /**
   * Fetches the current invoice based on the route parameter and updates the invoice state observable.
   */
  private getCurrentInvoice(): void {
    this.invoiceState$ = this.activatedRoute.paramMap.pipe(
      map((params: ParamMap) => params.get(INVOICE_ID)),
      switchMap(idStr => {
        const id = idStr ? Number(idStr) : null;
        if (id === null || isNaN(id)) {
          return of({ dataState: DataState.ERROR, error: 'Invalid invoice ID' });
        }
        return this.customerService.getInvoice$(id).pipe(
          map(response => {
            this.dataSubject.next(response);
            return { dataState: DataState.LOADED, appData: response };
          }),
          startWith({ dataState: DataState.LOADING }),
          catchError((error: string) => of({ dataState: DataState.ERROR, error }))
        );
      })
    );
  }

  /**
   * Exports the current invoice as a PDF file by downloading it from the server.
   */
  exportAsPDF(): void {
    const invoiceId = this.dataSubject.value?.data?.invoice?.id;
    const invoiceNumber = this.dataSubject.value?.data?.invoice?.invoiceNumber ?? 'unknown';
    if (!invoiceId) {
      console.error('No invoice ID found');
      return;
    }
    this.customerService.downloadInvoicePdf$(invoiceId).subscribe({
      next: (blob: Blob) => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `invoice-${invoiceNumber}.pdf`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
      },
      error: (err) => {
        console.error('Error downloading PDF:', err);
      }
    });
  }
}