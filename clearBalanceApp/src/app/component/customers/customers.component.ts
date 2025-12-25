import { Component, OnInit } from '@angular/core';
import { NgForm } from '@angular/forms';
import { Router } from '@angular/router';
import { Observable, BehaviorSubject, catchError, map, of, startWith } from 'rxjs';
import { slideBlur } from 'src/app/animations/animations';
import { DataState } from 'src/app/enum/datastate.enum';
import { Customer, CustomerPage } from 'src/app/interface/customer';
import { CustomHttpResponse } from 'src/app/interface/customhttpresponse';
import { State } from 'src/app/interface/state';
import { CustomerService } from 'src/app/service/customer.service';
import { TooltipService } from 'src/app/service/tooltip.service';

@Component({
  selector: 'app-customers',
  templateUrl: './customers.component.html',
  styleUrls: ['./customers.component.css'],
  animations: [
    slideBlur
  ]
})
export class CustomersComponent implements OnInit {
 
  searchTerm: string = '';
  customerPageSize: number = 10;
  customersState$!: Observable<State<CustomHttpResponse<CustomerPage>>>;

  isLoading$!: Observable<boolean>;
  private dataSubject: BehaviorSubject<CustomHttpResponse<CustomerPage> | null>;
  private isLoadingSubject: BehaviorSubject<boolean>;
  readonly DataState = DataState;

  constructor(
    private customerService: CustomerService,
    private tooltipService: TooltipService,
    private router: Router
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
   * Handles the search form submission to filter customers by name.
   *
   * @param searchForm - The form containing the search term
   */
  searchCustomers(searchForm: NgForm): void {
    this.searchTerm = searchForm.value.name || '';
    this.getCustomers(0, this.customerPageSize);
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
    this.customerService.downloadAllCustomersExcel$().subscribe({
      next: (blob: Blob) => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `customers_report_${new Date().toISOString().replace(/[:.]/g, '-')}.xlsx`;
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
   * Downloads all customers as a CSV file by calling the service and triggers a file download in the browser.
   */
  downloadAllCustomersCsv(): void {
    this.customerService.downloadAllCustomersCsv$().subscribe({
      next: (blob: Blob) => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `customers_report_${new Date().toISOString().replace(/[:.]/g, '-')}.csv`;
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
   * Resets the search term and reloads all customers from the first page.
   */
  resetSearch(): void {
    this.searchTerm = '';
    this.getCustomers(0, this.customerPageSize);
    this.initializeSearchTooltips();
  }

  /**
   * Navigates to the selected customer's detail page.
   *
   * @param customer - The selected customer
   */
  selectCustomer(customer: Customer) {
    this.router.navigate(['/customer', customer.id]);
  }
}
