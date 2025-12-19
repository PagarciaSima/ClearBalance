import { Component, OnInit } from '@angular/core';
import { NgForm } from '@angular/forms';
import { ActivatedRoute } from '@angular/router';
import { Observable, BehaviorSubject, catchError, map, of, startWith } from 'rxjs';
import { slideBlur } from 'src/app/animations/animations';
import { DataState } from 'src/app/enum/datastate.enum';
import { Customer, CustomerPage } from 'src/app/interface/customer';
import { CustomHttpResponse } from 'src/app/interface/customhttpresponse';
import { State } from 'src/app/interface/state';
import { User } from 'src/app/interface/user';
import { CustomerService } from 'src/app/service/customer.service';
import { TooltipService } from 'src/app/service/tooltip.service';

@Component({
  selector: 'app-customer',
  templateUrl: './customer.component.html',
  styleUrls: ['./customer.component.css'],
  animations: [
    slideBlur
  ]
})
export class CustomerComponent implements OnInit {

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

  ngAfterViewInit(): void {
      this.tooltipService.initialize();
  }

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
}
