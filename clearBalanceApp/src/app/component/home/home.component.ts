import { AfterViewInit, Component, OnDestroy } from '@angular/core';
import { BehaviorSubject, Observable, catchError, map, of, startWith } from 'rxjs';
import { slideBlur } from 'src/app/animations/animations';
import { DataState } from 'src/app/enum/datastate.enum';
import { Customer, CustomerData } from 'src/app/interface/customer';
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
  homeState$!: Observable<State<CustomHttpResponse<CustomerData>>>;
  isLoading$!: Observable<boolean>;
  showLogs$!: Observable<boolean>;
  private dataSubject: BehaviorSubject<CustomHttpResponse<CustomerData> | null>;
  private isLoadingSubject: BehaviorSubject<boolean>;
  private showLogsSubject: BehaviorSubject<boolean>;

  readonly DataState = DataState;

  constructor(
    private userService: UserService,
    private customerService: CustomerService,
    private tooltipService: TooltipService
  ) { 
    this.dataSubject = new BehaviorSubject<CustomHttpResponse<CustomerData> | null>(null);
    this.isLoadingSubject = new BehaviorSubject<boolean>(false);
    this.showLogsSubject = new BehaviorSubject<boolean>(true);
  }


  // ======= ANGULAR LIFECYCLE HOOKS =======
  ngOnInit(): void {
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
  getCustomers(page: number = 0, size: number = this.customerPageSize) {
    this.customerPageSize = size;
    this.homeState$ = this.customerService.customers$(page, size)
      .pipe(
        map(response => {
          console.log(response);
          this.dataSubject.next(response);
          // Esperar a que el DOM se actualice y luego inicializar popovers
          setTimeout(() => {
            const popoverTriggerList = Array.from(document.querySelectorAll('[data-bs-toggle="popover"]'));
            // @ts-ignore
            popoverTriggerList.forEach(el => new window.bootstrap.Popover(el));
          }, 0);
          return { dataState: DataState.LOADED, appData: response };
        }),
        startWith({ dataState: DataState.LOADING }),
        catchError((error: string) => {
          return of({ dataState: DataState.ERROR, error });
        })
      );
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

  selectCustomer(_t45: Customer) {
    throw new Error('Method not implemented.');
  }
}
