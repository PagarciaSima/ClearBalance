
import { AfterViewChecked, Component, OnInit } from '@angular/core';
import { NgForm } from '@angular/forms';
import { BehaviorSubject, catchError, map, Observable, of, startWith } from 'rxjs';
import { slideBlur } from 'src/app/animations/animations';
import { DataState } from 'src/app/enum/datastate.enum';
import { Customer } from 'src/app/interface/customer';
import { CustomHttpResponse } from 'src/app/interface/customhttpresponse';
import { Invoice } from 'src/app/interface/invoice';
import { InvoiceService } from 'src/app/interface/invoiceservice';
import { State } from 'src/app/interface/state';
import { User } from 'src/app/interface/user';
import { CustomerService } from 'src/app/service/customer.service';
import { NotificationService } from 'src/app/service/notification.service';
import { TooltipService } from 'src/app/service/tooltip.service';

declare var bootstrap: any;

@Component({
  selector: 'app-newinvoice',
  templateUrl: './newinvoice.component.html',
  styleUrls: ['./newinvoice.component.css'],
  animations: [
    slideBlur
  ]
})
export class NewinvoiceComponent implements OnInit, AfterViewChecked {
  newInvoiceState$: Observable<State<CustomHttpResponse<{ user: User; customers: Customer[] }>>> | null = null;
  private dataSubject = new BehaviorSubject<CustomHttpResponse<{ user: User; customers: Customer[] }> | null>(null);
  private isLoadingSubject = new BehaviorSubject<boolean>(false);
  isLoading$ = this.isLoadingSubject.asObservable();
  readonly DataState = DataState;

  // Dynamic services subform state for InvoiceService[]
  servicesList: InvoiceService[] = [];
  serviceForm: InvoiceService = { description: '', price: 0, quantity: 1 };

  constructor(
    private customerService: CustomerService,
    private tooltipService: TooltipService,
    private notificationService: NotificationService
  ) { }

  /**
   * Initializes the component by setting up the new invoice state observable and initializing tooltips.
   */
  ngOnInit(): void {
    this.newInvoiceState$ = of({ dataState: DataState.LOADED, appData: null });
    this.tooltipService.initialize();
    this.getNewInvoiceData();
  }

   ngAfterViewChecked() {
    // Inicializa todos los tooltips de Bootstrap en la vista
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.forEach((tooltipTriggerEl: HTMLElement) => {
      if (!tooltipTriggerEl.getAttribute('data-bs-initialized')) {
        new bootstrap.Tooltip(tooltipTriggerEl);
        tooltipTriggerEl.setAttribute('data-bs-initialized', 'true');
      }
    });
  }

  /**
   * Fetches the data required for creating a new invoice and updates the component state accordingly.
   * @return void
   */
  private getNewInvoiceData(): void {
    this.newInvoiceState$ = this.customerService.getNewInvoiceData$()
      .pipe(
        map(response => {
          this.dataSubject.next(response);
          this.notificationService.onSuccess('Invoice data loaded successfully.');
          return { dataState: DataState.LOADED, appData: response };
        }),
        startWith({ dataState: DataState.LOADING }),
        catchError((error: string) => {
          this.notificationService.onError('Failed to load invoice data: ' + error);
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
    if (this.servicesList.length === 0) {
      this.notificationService.onError('Please add at least one service to the invoice.');
      return;
    }
    if (this.dataSubject.value) {
      this.dataSubject.next({ ...this.dataSubject.value, message: null });
    }
    this.isLoadingSubject.next(true);
    newInvoiceForm.form.patchValue({ services: this.servicesList, total: this.total });
    const invoice: Invoice = { ...newInvoiceForm.value, services: this.servicesList, total: this.total };
    this.newInvoiceState$ = this.customerService.addInvoiceToCustomer$(newInvoiceForm.value.customerId, invoice)
      .pipe(
        map(response => {
          newInvoiceForm.reset({
            customerId: '',
            status: '',
            services: '',
            total: '',
            date: ''
          });
          this.servicesList = [];
          this.isLoadingSubject.next(false);
          this.dataSubject.next(response);
          this.notificationService.onSuccess('Invoice created successfully.');
          return { dataState: DataState.LOADED, appData: this.dataSubject.value };
        }),
        startWith({ dataState: DataState.LOADED, appData: this.dataSubject.value }),
        catchError((error: string) => {
          this.isLoadingSubject.next(false);
          this.notificationService.onError('Failed to create invoice: ' + error);
          return of({ dataState: DataState.LOADED, error });
        })
      );
  }

  /**
   * Gets the total amount for the invoice based on the services list.
   */
  get total(): number {
    return this.servicesList.reduce((sum, s) => sum + (s.price * s.quantity), 0);
  }

  /**
 * Add a service to the list and reset the temp form
 */
  addService(): void {
    if (this.serviceForm.description && this.serviceForm.price != null && this.serviceForm.quantity != null) {
      this.servicesList.push({
        description: this.serviceForm.description.trim(),
        price: this.serviceForm.price,
        quantity: this.serviceForm.quantity
      });
      this.serviceForm = { description: '', price: 0, quantity: 1 };
    }
  }

  /**
   * Remove a service from the list by index
   */
  removeService(index: number): void {
    this.servicesList.splice(index, 1);
  }
}