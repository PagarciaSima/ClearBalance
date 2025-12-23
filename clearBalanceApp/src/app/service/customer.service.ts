import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { catchError, Observable, tap, throwError, map } from 'rxjs';
import { CustomHttpResponse } from '../interface/customhttpresponse';
import { Customer, CustomerPage } from '../interface/customer';
import { Stats } from '../interface/stats';
import { User } from '../interface/user';
import { Invoice } from '../interface/invoice';
import { InvoiceService } from '../interface/invoiceservice';
import { Page } from '../interface/page';

@Injectable({
  providedIn: 'root'
})
export class CustomerService {

  private readonly server: string = 'http://localhost:8080';

  constructor(private http: HttpClient) { }

  /**
   * Fetches a paginated list of customers from the server.
   * 
   * @param page - The page number to retrieve (default is 0)
   * @returns An Observable emitting a CustomHttpResponse containing customer data
   */
  customers$(page: number = 0, size: number = 10): Observable<CustomHttpResponse<CustomerPage>> {
    return this.http.get<CustomHttpResponse<CustomerPage>>(`${this.server}/customer/list?page=${page}&size=${size}`)
      .pipe(
        tap(console.log),
        catchError(this.handleError)
      );
  }


  /**
   * Searches for customers by name with pagination support.
   *
   * @param name - The name (or partial name) of the customer to search for. If omitted, returns all customers.
   * @param page - The page number to retrieve (default is 0)
   * @param size - The number of customers per page (default is 10)
   * @returns An Observable emitting a CustomHttpResponse containing the paginated customer data
   */
  searchCustomers$(name?: string, page: number = 0, size: number = 10): Observable<CustomHttpResponse<CustomerPage>> {
    const params = [
      name ? `name=${encodeURIComponent(name)}` : '',
      `page=${page}`,
      `size=${size}`
    ].filter(Boolean).join('&');
    return this.http.get<CustomHttpResponse<CustomerPage>>(`${this.server}/customer/search?${params}`)
      .pipe(
        tap(console.log),
        catchError(this.handleError)
      );
  }

  /**
 * Creates a new customer by sending a POST request to the backend.
 *
 * @param customer - The customer object to create
 * @returns An Observable emitting a CustomHttpResponse containing the created customer and user
 */
  newCustomers$(customer: Customer): Observable<CustomHttpResponse<{ user: User; customer: Customer }>> {
    return this.http.post<CustomHttpResponse<{ user: User; customer: Customer }>>(
      `${this.server}/customer/create`,
      customer
    ).pipe(
      tap(console.log),
      catchError(this.handleError)
    );
  }

  /**
   * Retrieves global statistics from the server.
   *
   * @returns An Observable emitting a CustomHttpResponse containing global stats data
   */
  getGlobalStats$(): Observable<CustomHttpResponse<{ user: User; stats: Stats }>> {
    return this.http.get<CustomHttpResponse<{ user: User; stats: Stats }>>(`${this.server}/customer/stats`)
      .pipe(
        tap(console.log),
        catchError(this.handleError)
      );
  }

  /**
   * Retrieves a customer by their unique ID from the backend.
   *
   * @param id - The unique identifier of the customer to retrieve
   * @returns An Observable emitting a CustomHttpResponse containing the user and customer data
   */
  getCustomer$(id: number): Observable<CustomHttpResponse<{ user: User; customer: Customer }>> {
    return this.http.get<CustomHttpResponse<{ user: User; customer: Customer }>>(
      `${this.server}/customer/get/${id}`
    ).pipe(
      tap(console.log),
      catchError(this.handleError)
    );
  }

  /**
   * Updates an existing customer by sending a PUT request to the backend.
   *
   * @param customer The customer object containing updated information.
   * @returns Observable containing the backend response with the authenticated user and updated customer.
   */
  updateCustomer(customer: Customer): Observable<CustomHttpResponse<{ user: User; customer: Customer }>> {
    return this.http.put<CustomHttpResponse<{ user: User; customer: Customer }>>(`${this.server}/customer/update`, customer);
  }

  /**
   * Fetches the authenticated user and all customers for new invoice creation.
   *
   * @returns An Observable emitting a CustomHttpResponse containing the user and customers list.
   */
  getNewInvoiceData$(): Observable<CustomHttpResponse<{ user: User; customers: Customer[] }>> {
    return this.http.get<CustomHttpResponse<{ user: User; customers: Customer[] }>>(
      `${this.server}/customer/invoice/new`
    ).pipe(
      tap(console.log),
      catchError(this.handleError)
    );
  }

  /**
  * Adds an invoice to a specific customer by sending a POST request to the backend.
  *
  * @param customerId - The unique identifier of the customer
  * @param invoice - The invoice object to add to the customer
  * @returns An Observable emitting a CustomHttpResponse containing the user and updated customers list
  */
  addInvoiceToCustomer$(customerId: number, invoice: Invoice): Observable<CustomHttpResponse<{ user: User; customers: Customer[] }>> {
    return this.http.post<CustomHttpResponse<{ user: User; customers: Customer[] }>>(
      `${this.server}/customer/invoice/addtocustomer/${customerId}`,
      invoice
    ).pipe(
      tap(console.log),
      catchError(this.handleError)
    );
  }

  /**
   * Retrieves a paginated list of invoices from the backend.
   *
   * @param page - The page number to retrieve (default is 0)
   * @param size - The number of invoices per page (default is 10)
   * @returns An Observable emitting a CustomHttpResponse containing the user and paginated invoices
   */
  getInvoices$(page: number = 0, size: number = 10): Observable<CustomHttpResponse<{ user: User; page: Page<Invoice> }>> {
    return this.http.get<CustomHttpResponse<{ user: User; page: any }>>(
      `${this.server}/customer/invoice/list?page=${page}&size=${size}`
    ).pipe(
      map(response => {
        // Si la respuesta no es paginada, la adaptamos
        if (response && response.data && response.data.page && !('content' in response.data.page)) {
          const invoice = response.data.page as Invoice;
          response.data.page = {
            content: [invoice],
            empty: false,
            first: true,
            last: true,
            number: 0,
            numberOfElements: 1,
            pageable: {
              pageNumber: 0,
              pageSize: 1,
              offset: 0,
              paged: true,
              unpaged: false,
              sort: { empty: true, sorted: false, unsorted: true }
            },
            size: 1,
            sort: { empty: true, sorted: false, unsorted: true },
            totalElements: 1,
            totalPages: 1
          };
        }
        return response as CustomHttpResponse<{ user: User; page: Page<Invoice> }>;
      }),
      tap(console.log),
      catchError(this.handleError)
    );
  }

  /**
   * Fetches a single invoice by its ID from the server.
   *
   * @param invoiceId - The ID of the invoice to retrieve
   * @returns An Observable emitting a CustomHttpResponse containing the invoice, customer, and user data
   */
  getInvoice$(invoiceId: number): Observable<CustomHttpResponse<{ user: User; invoice: Invoice; customer: Customer }>> {
    return this.http.get<CustomHttpResponse<{ user: User; invoice: Invoice; customer: Customer }>>(
      `${this.server}/customer/invoice/get/${invoiceId}`
    ).pipe(
      tap(console.log),
      catchError(this.handleError)
    );
  }

  /**
   * Descarga el PDF de una factura generado por el backend (JasperReports).
   *
   * @param invoiceId - El ID de la factura
   * @returns Observable con el blob del PDF
   */
  downloadInvoicePdf$(invoiceId: number): Observable<Blob> {
    return this.http.get(`${this.server}/customer/invoice/${invoiceId}/pdf`, {
      responseType: 'blob'
    }).pipe(
      tap(() => console.log('PDF downloaded for invoice', invoiceId)),
      catchError(this.handleError)
    );
  }

  /**
   * Handles HTTP errors from service requests.
   * Determines if the error originated from client-side or server-side and formats an appropriate error message.
   * 
   * @param error - The HttpErrorResponse object containing error details
   * @returns An Observable that throws a formatted error message string
   * 
   * @remarks
   * - For client-side errors (ErrorEvent), returns the error message
   * - For server-side errors, prioritizes custom reason from error.error.reason
   * - Falls back to standard HTTP error status and message if no custom reason exists
   */
  handleError(error: HttpErrorResponse): Observable<never> {
    return throwError(() => error);
  }

}
