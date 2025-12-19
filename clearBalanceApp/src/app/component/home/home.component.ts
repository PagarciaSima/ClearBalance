import { AfterViewInit, Component, OnDestroy } from '@angular/core';
import { Router } from '@angular/router';
import { BehaviorSubject, Observable, catchError, map, of, startWith } from 'rxjs';
import { slideBlur } from 'src/app/animations/animations';
import { DataState } from 'src/app/enum/datastate.enum';
import { Customer, CustomerPage } from 'src/app/interface/customer';
import { CustomHttpResponse } from 'src/app/interface/customhttpresponse';
import { State } from 'src/app/interface/state';
import { CustomerService } from 'src/app/service/customer.service';
import { TooltipService } from 'src/app/service/tooltip.service';
import { UserService } from 'src/app/service/user.service';

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
    this.router.navigate(['/customer', customer.id]);
  }
}
