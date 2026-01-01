import { AfterViewInit, ChangeDetectionStrategy, Component, OnInit } from '@angular/core';
import { NgForm } from '@angular/forms';
import { BehaviorSubject, catchError, map, Observable, of, startWith } from 'rxjs';
import { slideBlur } from 'src/app/animations/animations';
import { DataState } from 'src/app/enum/datastate.enum';
import { Customer } from 'src/app/interface/customer';
import { CustomHttpResponse } from 'src/app/interface/customhttpresponse';
import { State } from 'src/app/interface/state';
import { User } from 'src/app/interface/user';
import { CustomerService } from 'src/app/service/customer.service';
import { TooltipService } from 'src/app/service/tooltip.service';
import { NotificationService } from 'src/app/service/notification.service';

@Component({
  selector: 'app-newcustomer',
  templateUrl: './newcustomer.component.html',
  styleUrls: ['./newcustomer.component.css'],
  animations: [
    slideBlur
  ],
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class NewcustomerComponent implements OnInit, AfterViewInit {

  newCustomerState$: Observable<State<CustomHttpResponse<Customer & User >>> | null = null;
  private dataSubject = new BehaviorSubject<any>(null);
  private isLoadingSubject = new BehaviorSubject<boolean>(false);
  isLoading$ = this.isLoadingSubject.asObservable();
  readonly DataState = DataState;

  constructor(
    private customerService: CustomerService,
    private tooltipService: TooltipService,
    private notificationService: NotificationService
  ) { }
  
  /**
   * Initializes Bootstrap tooltips after the view is fully initialized.
   */
  ngAfterViewInit(): void {
    this.tooltipService.initialize();
  }

  /**
   * Initializes the component by setting up the new customer state observable.
   */
  ngOnInit(): void {
    this.newCustomerState$ = of({ dataState: DataState.LOADED, appData: null });
  }

  /**
   * Creates a new customer using the provided form data.
   *
   * @param newCustomerForm - The form containing new customer data
   */
  createCustomer(newCustomerForm: NgForm): void {
    this.isLoadingSubject.next(true);
    this.newCustomerState$ = this.customerService.newCustomers$(newCustomerForm.value)
      .pipe(
        map(response => {
          console.log(response);
          newCustomerForm.reset({ type: 'INDIVIDUAL', status: 'ACTIVE' });
          this.isLoadingSubject.next(false);
          this.notificationService.onSuccess('Customer created successfully.');
          return { dataState: DataState.LOADED, appData: this.dataSubject.value };
        }),
        startWith({ dataState: DataState.LOADED, appData: this.dataSubject.value }),
        catchError((error: any) => {
          this.isLoadingSubject.next(false);
          console.log(error);
          let errorMessage = 'Failed to create customer.';
          if (error && error.error && error.error.reason) {
            errorMessage = error.error.reason;
          } else if (error && error.message) {
            errorMessage = error.message;
          }
          this.notificationService.onError(errorMessage);
          return of({ dataState: DataState.LOADED, error: errorMessage });
        })
      );
  }
}
