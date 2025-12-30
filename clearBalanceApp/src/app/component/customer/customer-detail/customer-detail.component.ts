
import { Component, OnInit } from '@angular/core';
import { NgForm } from '@angular/forms';
import { ActivatedRoute } from '@angular/router';
import { BehaviorSubject, catchError, map, Observable, of, startWith } from 'rxjs';
import { slideBlur } from 'src/app/animations/animations';
import { DataState } from 'src/app/enum/datastate.enum';
import { Customer } from 'src/app/interface/customer';
import { CustomHttpResponse } from 'src/app/interface/customhttpresponse';
import { State } from 'src/app/interface/state';
import { User } from 'src/app/interface/user';
import { CustomerService } from 'src/app/service/customer.service';
import { TooltipService } from 'src/app/service/tooltip.service';

@Component({
  selector: 'app-customer-detail',
  templateUrl: './customer-detail.component.html',
  styleUrls: ['./customer-detail.component.css'],
  animations: [
    slideBlur
  ]
})
export class CustomerDetailComponent implements OnInit {

  customerState$!: Observable<State<CustomHttpResponse<{ user: User; customer: Customer }>>>;
  isLoading$!: Observable<boolean>;
  private dataSubject: BehaviorSubject<CustomHttpResponse<{ user: User; customer: Customer }> | null>;
  private isLoadingSubject: BehaviorSubject<boolean>;
  private readonly CUSTOMER_ID_PARAM: string = 'id';
  readonly DataState = DataState;

  constructor(
    private customerService: CustomerService,
    private tooltipService: TooltipService,
    private activatedRoute: ActivatedRoute
  ) {
    this.dataSubject = new BehaviorSubject<CustomHttpResponse<{ user: User; customer: Customer }> | null>(null);
    this.isLoadingSubject = new BehaviorSubject<boolean>(false);
  }

  // ======= ANGULAR LIFECYCLE HOOKS =======
  ngOnInit(): void {
    this.activatedRoute.params.subscribe(params => {
      const customerId = + params[this.CUSTOMER_ID_PARAM];
      this.customerState$ = this.getCustomerDetails(customerId);
    });
    // Initialize loading observable
    this.isLoading$ = this.isLoadingSubject.asObservable();
  }

  /**
   * Initializes tooltips after the view has been fully initialized.
   */
  ngAfterViewInit(): void {
      this.tooltipService.initialize();
  }

  /**
   * Fetches customer details based on the provided customer ID.
   *
   * @param customerId - The ID of the customer to retrieve
   * @returns An Observable emitting the state of the customer details retrieval
   */
  getCustomerDetails(customerId: number): Observable<State<CustomHttpResponse<{ user: User; customer: Customer }>>> {
    return this.customerService.getCustomer$(customerId)
      .pipe(
        map(response => {
          console.log("details ", response);
          this.dataSubject.next(response);
          return { dataState: DataState.LOADED, appData: response };
        }),
        startWith({ dataState: DataState.LOADING }),
        catchError((error: string) => of({ dataState: DataState.ERROR, error }))
      );
  }

  /**
   * Updates customer information based on the provided form data.
   *
   * @param customerForm - The form containing updated customer information
   */
  updateCustomer(customerForm: NgForm): void {
    this.isLoadingSubject.next(true);
    this.customerState$ = this.customerService.updateCustomer(customerForm.value)
      .pipe(
        map(response => {
          console.log("update ", response);
          this.dataSubject.next(response);
          this.isLoadingSubject.next(false);
          return { dataState: DataState.LOADED, appData: this.dataSubject.value };
        }),
        startWith({ dataState: DataState.LOADING }),
        catchError((error: string) => {
          this.isLoadingSubject.next(false);
          return of({ dataState: DataState.ERROR, error })
        })
      );
  }

  /**
   * Opens the user's address in Google Maps in a new tab.
   */
  viewOnMap(address?: string): void {
    if (address && address.trim()) {
      const encodedAddress = encodeURIComponent(address);
      const mapsUrl = `https://www.google.com/maps/search/?api=1&query=${encodedAddress}`;
      window.open(mapsUrl, '_blank', 'noopener,noreferrer');
    }
  }

  /**
   * Calculates the total amount of all invoices for the current customer.
   * @returns The sum of all invoice totals, or 0 if none.
   */
  getTotalInvoices(): number {
    const invoices = this.dataSubject.value?.data?.customer?.invoices || [];
    return invoices.reduce((sum, invoice) => sum + (invoice.total || 0), 0);
  }
}
