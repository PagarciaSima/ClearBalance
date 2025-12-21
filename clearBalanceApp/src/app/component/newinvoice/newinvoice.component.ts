import { Component } from '@angular/core';
import { NgForm } from '@angular/forms';
import { Observable, BehaviorSubject, map, startWith, catchError, of } from 'rxjs';
import { slideBlur } from 'src/app/animations/animations';
import { DataState } from 'src/app/enum/datastate.enum';
import { Customer } from 'src/app/interface/customer';
import { CustomHttpResponse } from 'src/app/interface/customhttpresponse';
import { State } from 'src/app/interface/state';
import { User } from 'src/app/interface/user';
import { CustomerService } from 'src/app/service/customer.service';
import { TooltipService } from 'src/app/service/tooltip.service';

@Component({
  selector: 'app-newinvoice',
  templateUrl: './newinvoice.component.html',
  styleUrls: ['./newinvoice.component.css'],
  animations: [
    slideBlur
  ]
})
export class NewinvoiceComponent {
  newInvoiceState$: Observable<State<CustomHttpResponse<{ user: User; customers: Customer[] }>>> | null = null;
  private dataSubject = new BehaviorSubject<CustomHttpResponse<{ user: User; customers: Customer[] }> | null>(null);
  private isLoadingSubject = new BehaviorSubject<boolean>(false);
  isLoading$ = this.isLoadingSubject.asObservable();
  readonly DataState = DataState;

  constructor(
    private customerService: CustomerService,
    private tooltipService: TooltipService
  ) {

  }

  /**
   * Initializes the component by setting up the new invoice state observable and initializing tooltips.
   */
  ngOnInit(): void {
    this.newInvoiceState$ = of({ dataState: DataState.LOADED, appData: null });
    this.tooltipService.initialize();
    this.getNewInvoiceData();
  }

  /**
   * Fetches the data required for creating a new invoice and updates the component state accordingly.
   * @return void
   */
  private getNewInvoiceData(): void {
    this.newInvoiceState$ = this.customerService.getNewInvoiceData$()
      .pipe(
        map(response => {
          console.log(response);
          this.dataSubject.next(response);
          return { dataState: DataState.LOADED, appData: response };
        }),
        startWith({ dataState: DataState.LOADING }),
        catchError((error: string) => {
          return of({ dataState: DataState.ERROR, error });
        })
      );
  }

  /**
   * Creates a new invoice using the provided form data.
   *
   * @param invoiceForm - The form containing new invoice data
   */
  createInvoice(newInvoiceForm: NgForm): void {
    if (this.dataSubject.value) {
      this.dataSubject.next({ ...this.dataSubject.value, message: null });
    }
    this.isLoadingSubject.next(true);
    this.newInvoiceState$ = this.customerService.addInvoiceToCustomer$(newInvoiceForm.value.customerId, newInvoiceForm.value)
      .pipe(
        map(response => {
          console.log(response);
          newInvoiceForm.reset({
            customerId: '',
            status: '',
            services: '',
            total: '',
            date: ''
          });
          this.isLoadingSubject.next(false);
          this.dataSubject.next(response);
          return { dataState: DataState.LOADED, appData: this.dataSubject.value };
        }),
        startWith({ dataState: DataState.LOADED, appData: this.dataSubject.value }),
        catchError((error: string) => {
          this.isLoadingSubject.next(false);
          return of({ dataState: DataState.LOADED, error })
        })
      )
  }
}
