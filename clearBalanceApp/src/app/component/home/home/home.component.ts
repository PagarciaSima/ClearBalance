import { AfterViewInit, Component, OnDestroy } from '@angular/core';
import { Router } from '@angular/router';
import { BehaviorSubject, Observable, catchError, map, of, startWith } from 'rxjs';
import { slideBlur } from 'src/app/animations/animations';
import { DataState } from 'src/app/enum/datastate.enum';
import { Customer, CustomerPage } from 'src/app/interface/customer';
import { CustomHttpResponse } from 'src/app/interface/customhttpresponse';
import { State } from 'src/app/interface/state';
import { CustomerService } from 'src/app/service/customer.service';
import { NotificationService } from 'src/app/service/notification.service';
import { TooltipService } from 'src/app/service/tooltip.service';

@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.css'],
  animations: [
    slideBlur
  ]
})
export class HomeComponent implements AfterViewInit, OnDestroy {

  customerPageSize: number = 10;
  homeState$!: Observable<State<CustomHttpResponse<CustomerPage>>>;
  isLoading$!: Observable<boolean>;
  private dataSubject: BehaviorSubject<CustomHttpResponse<CustomerPage> | null>;
  private isLoadingSubject: BehaviorSubject<boolean>;
  readonly DataState = DataState;

  constructor(
    private customerService: CustomerService,
    private notificationService: NotificationService,
    private tooltipService: TooltipService,
    private router: Router
  ) { 
    this.dataSubject = new BehaviorSubject<CustomHttpResponse<CustomerPage> | null>(null);
    this.isLoadingSubject = new BehaviorSubject<boolean>(false);
  }


  // ======= ANGULAR LIFECYCLE HOOKS =======
  ngOnInit(): void {
    // Initialize loading observable
    this.isLoading$ = this.isLoadingSubject.asObservable();
    this.getCustomers();
  }

  ngAfterViewInit(): void {
    this.tooltipService.initialize();
  }

  ngOnDestroy(): void {
    this.tooltipService.hideAll();
  }

  /**
   * Fetches customers with pagination support.
   * @param page The page index (zero-based)
   * @param size The page size
   */
  /**
   * Fetches customers with pagination support and manages loading state.
   * @param page The page index (zero-based)
   * @param size The page size
   */
  getCustomers(page: number = 0, size: number = this.customerPageSize): void {
    this.customerPageSize = size;
    this.isLoadingSubject.next(true);
    this.homeState$ = this.customerService.customers$(page, size)
      .pipe(
        map(response => {
          this.dataSubject.next(response);
          this.initializePopovers();
          this.isLoadingSubject.next(false);
          this.notificationService.onSuccess('Customers loaded successfully.');
          return { dataState: DataState.LOADED, appData: response };
        }),
        startWith({ dataState: DataState.LOADING }),
        catchError((error: string) => {
          this.isLoadingSubject.next(false);
          this.notificationService.onError('Failed to load customers: ' + error);
          return of({ dataState: DataState.ERROR, error });
        })
      );
  }
  
  /**
   * Initializes Bootstrap popovers for customer images.
   */
  private initializePopovers() {
    setTimeout(() => {
      const popoverTriggerList = Array.from(document.querySelectorAll('[data-bs-toggle="popover"]'));
      // @ts-ignore
      popoverTriggerList.forEach(el => new window.bootstrap.Popover(el));
    }, 0);
  }

  /**
   * Handles page change event from pagination component.
   * @param page The new page index (zero-based)
   */

  /**
   * Handles page change event from pagination component.
   * @param page The new page index (zero-based)
   */
  onCustomerPageChange(page: number): void {
    this.getCustomers(page, this.customerPageSize);
  }

  /**
   * Handles page size change event from pagination component.
   * @param newSize The new page size
   */
  onCustomerPageSizeChange(newSize: number): void {
    this.customerPageSize = newSize;
    this.getCustomers(0, newSize);
  }

  /**
   * Navigates to the selected customer's detail page.
   *
   * @param customer - The selected customer
   */
  selectCustomer(customer: Customer) {
    this.router.navigate(['/customers/customer', customer.id]);
  }

  /**
   * Downloads all customers as an Excel file by calling the service and triggers a file download in the browser.
   */
  downloadAllCustomersExcel(): void {
    this.isLoadingSubject.next(true);
    
    this.customerService.downloadAllCustomersExcel$().subscribe({
      next: (blob: Blob) => {
        if (blob && blob.size > 0) {
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `customers_report_${new Date().toISOString().replace(/[:.]/g, '-')}.xlsx`;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          window.URL.revokeObjectURL(url);
          this.notificationService.onSuccess('Excel file downloaded successfully.');
        } else {
          this.notificationService.onError('Received empty file from server.');
        }
        this.isLoadingSubject.next(false);
      },
      error: (err) => {
        console.error('Excel download error:', err);
        const errorMessage = err?.error?.reason || err?.message || `Failed to download Excel file. Status: ${err.status}`;
        this.notificationService.onError(errorMessage);
        this.isLoadingSubject.next(false);
      }
    });
  }
}
