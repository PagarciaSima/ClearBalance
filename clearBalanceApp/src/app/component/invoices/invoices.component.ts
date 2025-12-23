import { ChangeDetectionStrategy, Component, OnInit } from '@angular/core';
import { BehaviorSubject, catchError, map, Observable, of, startWith } from 'rxjs';
import { slideBlur } from 'src/app/animations/animations';
import { DataState } from 'src/app/enum/datastate.enum';
import { CustomHttpResponse } from 'src/app/interface/customhttpresponse';
import { Invoice } from 'src/app/interface/invoice';
import { Page } from 'src/app/interface/page';
import { State } from 'src/app/interface/state';
import { User } from 'src/app/interface/user';
import { CustomerService } from 'src/app/service/customer.service';
import { TooltipService } from 'src/app/service/tooltip.service';

/**
 * Component for displaying the list of invoices.
 */
@Component({
  selector: 'app-invoices',
  templateUrl: './invoices.component.html',
  styleUrls: ['./invoices.component.css'],
  animations: [slideBlur],
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class InvoicesComponent implements OnInit {

  invoicesState$!: Observable<State<CustomHttpResponse<{ user: User; page: Page<Invoice> } | null>>>;
  private dataSubject = new BehaviorSubject<CustomHttpResponse<{ user: User; page: Page<Invoice> }> | null>(null);
  private isLoadingSubject = new BehaviorSubject<boolean>(false);
  isLoading$ = this.isLoadingSubject.asObservable();
  readonly DataState = DataState;

  invoicePageSize: number = 10;

  constructor(
    private customerService: CustomerService,
    private tooltipService: TooltipService
  ) { }

  ngOnInit(): void {
    this.loadInvoices();
    this.tooltipService.initialize();
  }

  /**
   * Downloads all invoices as an Excel file by calling the service and triggers a file download in the browser.
   */
  downloadAllInvoicesExcel(): void {
    this.customerService.downloadAllInvoicesExcel$().subscribe({
      next: (blob: Blob) => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `all_invoices_${new Date().toISOString().replace(/[:.]/g, '-')}.xlsx`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
      },
      error: (err) => {
        // Optionally, handle error (e.g., show a notification)
        console.error('Failed to download Excel file', err);
      }
    });
  }

  /**
   * Loads all invoices from the backend and updates the component state.
   * @param page The page index (zero-based)
   * @param size The page size
   */
  loadInvoices(page: number = 0, size: number = this.invoicePageSize): void {
    this.invoicePageSize = size;
    this.isLoadingSubject.next(true);
    this.invoicesState$ = this.customerService.getInvoices$(page, size)
      .pipe(
        map(response => {
          this.isLoadingSubject.next(false);
          this.dataSubject.next(response);
          return { dataState: DataState.LOADED, appData: response };
        }),
        startWith({ dataState: DataState.LOADING }),
        catchError((error: string) => {
          this.isLoadingSubject.next(false);
          return of({ dataState: DataState.ERROR, error });
        })
      );
  }

  /**
  * Downloads all invoices as a CSV file by calling the service and triggers a file download in the browser.
  */
  downloadAllInvoicesCsv(): void {
    this.customerService.downloadAllInvoicesCsv$().subscribe({
      next: (blob: Blob) => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `facturas_simple_${new Date().toISOString().replace(/[:.]/g, '-')}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
      },
      error: (err) => {
        // Optionally, handle error (e.g., show a notification)
        console.error('Failed to download CSV file', err);
      }
    });
  }

  /**
   * Handles page change event from pagination component.
   * @param page The new page index (zero-based)
   */
  onInvoicePageChange(page: number): void {
    this.loadInvoices(page, this.invoicePageSize);
  }

  /**
   * Handles page size change event from pagination component.
   * @param newSize The new page size
   */
  onInvoicePageSizeChange(newSize: number): void {
    this.invoicePageSize = newSize;
    this.loadInvoices(0, newSize);
  }
}