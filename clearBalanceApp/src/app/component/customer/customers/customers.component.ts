import { Component, OnInit } from '@angular/core';
import { NgForm } from '@angular/forms';
import { Router } from '@angular/router';
import { BehaviorSubject, catchError, map, Observable, of, startWith } from 'rxjs';
import { slideBlur } from 'src/app/animations/animations';
import { DataState } from 'src/app/enum/datastate.enum';
import { Customer, CustomerPage } from 'src/app/interface/customer';
import { CustomHttpResponse } from 'src/app/interface/customhttpresponse';
import { State } from 'src/app/interface/state';
import { CustomerService } from 'src/app/service/customer.service';
import { TooltipService } from 'src/app/service/tooltip.service';
import { NotificationService } from 'src/app/service/notification.service';

@Component({
  selector: 'app-customers',
  templateUrl: './customers.component.html',
  styleUrls: ['./customers.component.css'],
  animations: [
    slideBlur
  ]
})
export class CustomersComponent implements OnInit {
  /**
   * Search term for filtering customers by name.
   */
  searchTerm: string = '';
  /**
   * Page size for paginated customer table.
   */
  customerPageSize: number = 10;
  /**
   * Observable for paginated customer state.
   */
  customersState$!: Observable<State<CustomHttpResponse<CustomerPage>>>;
  /**
   * Observable for loading state.
   */
  isLoading$!: Observable<boolean>;
  private dataSubject: BehaviorSubject<CustomHttpResponse<CustomerPage> | null>;
  private isLoadingSubject: BehaviorSubject<boolean>;
  /**
   * Holds all customers for the map (not paginated).
   */
  allCustomers: Customer[] = [];
  readonly DataState = DataState;

  constructor(
    private customerService: CustomerService,
    private tooltipService: TooltipService,
    private router: Router,
    private notificationService: NotificationService
  ) {
    this.dataSubject = new BehaviorSubject<CustomHttpResponse<CustomerPage> | null>(null);
    this.isLoadingSubject = new BehaviorSubject<boolean>(false);
  }


  // ======= ANGULAR LIFECYCLE HOOKS =======

  /**
   * Initializes the component by setting up the loading observable and fetching the initial set of customers.
   */
  ngOnInit(): void {
    // Initialize loading observable
    this.isLoading$ = this.isLoadingSubject.asObservable();
    this.getCustomers();
    this.loadAllCustomersForMap();
  }

  /**
   * Loads all customers (no pagination) for the map display.
   */
  private loadAllCustomersForMap(): void {
    this.customerService.getAllCustomers$().subscribe({
      next: (response) => {
        if (response && response.data && Array.isArray(response.data.customers)) {
          this.allCustomers = response.data.customers;
        } else {
          this.allCustomers = [];
        }
      },
      error: (err) => {
        this.allCustomers = [];
        this.notificationService.onError('Failed to load all customers for map.');
        console.error('Failed to load all customers for map', err);
      }
    });
  }

  /**
   * Initializes Bootstrap tooltips after the view is fully initialized.
   */
  ngAfterViewInit(): void {
    this.tooltipService.initialize();
  }

  /**
   * Initializes tooltips for the search functionality.
   */
  private initializeSearchTooltips(): void {
    setTimeout(() => this.tooltipService.initialize(), 0);
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
  /**
   * Fetches customers with pagination and search support.
   * If a search term is present, uses searchCustomers$; otherwise, uses customers$.
   *
   * @param page - The page index (zero-based)
   * @param size - The page size
   */
  getCustomers(page: number = 0, size: number = this.customerPageSize): void {
    this.customerPageSize = size;
    this.isLoadingSubject.next(true);
    const obs = this.searchTerm
      ? this.customerService.searchCustomers$(this.searchTerm, page, size)
      : this.customerService.customers$(page, size);
    this.customersState$ = obs.pipe(
      map(response => {
        this.dataSubject.next(response);
        this.initialiceCustomerImagePopOver();
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
   * Handles the search form submission to filter customers by name.
   *
   * @param searchForm - The form containing the search term
   */
  searchCustomers(searchForm: NgForm): void {
    this.searchTerm = searchForm.value.name || '';
    this.getCustomers(0, this.customerPageSize);
    this.loadAllCustomersForMap();
    this.initializeSearchTooltips();
  }

  /**
   * Handles page change event from the pagination component.
   *
   * @param page - The new page index (zero-based)
   */
  onPageChange(page: number): void {
    this.getCustomers(page, this.customerPageSize);
  }

  /**
   * Handles page size change event from the pagination component.
   *
   * @param size - The new page size
   */
  onPageSizeChange(size: number): void {
    this.customerPageSize = size;
    this.getCustomers(0, size);
  }

  /**
   * Initializes Bootstrap popovers for customer images.
   */
  private initialiceCustomerImagePopOver() {
    setTimeout(() => {
      const popoverTriggerList = Array.from(document.querySelectorAll('[data-bs-toggle="popover"]'));
      // @ts-ignore
      popoverTriggerList.forEach(el => new window.bootstrap.Popover(el));
    }, 0);
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
        const errorMessage = err?.error?.reason || err?.message || 'Failed to download Excel file.';
        this.notificationService.onError(errorMessage);
        this.isLoadingSubject.next(false);
      }
    });
  }

  /**
   * Downloads all customers as a CSV file by calling the service and triggers a file download in the browser.
   */
  downloadAllCustomersCsv(): void {
    this.isLoadingSubject.next(true);
    
    this.customerService.downloadAllCustomersCsv$().subscribe({
      next: (blob: Blob) => {
        if (blob && blob.size > 0) {
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `customers_report_${new Date().toISOString().replace(/[:.]/g, '-')}.csv`;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          window.URL.revokeObjectURL(url);
          this.notificationService.onSuccess('CSV file downloaded successfully.');
        } else {
          this.notificationService.onError('Received empty file from server.');
        }
        this.isLoadingSubject.next(false);
      },
      error: (err) => {
        console.error('CSV download error:', err);
        const errorMessage = err?.error?.reason || err?.message || 'Failed to download CSV file.';
        this.notificationService.onError(errorMessage);
        this.isLoadingSubject.next(false);
      }
    });
  }

  /**
   * Resets the search term and reloads all customers from the first page.
   */
  resetSearch(): void {
    this.searchTerm = '';
    this.getCustomers(0, this.customerPageSize);
    this.loadAllCustomersForMap();
    this.initializeSearchTooltips();
  }

  /**
   * Navigates to the selected customer's detail page.
   *
   * @param customer - The selected customer
   */
  selectCustomer(customer: Customer) {
    this.router.navigate(['/customers/customer', customer.id]);
  }
}
