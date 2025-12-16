import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { catchError, Observable, tap, throwError } from 'rxjs';
import { CustomHttpResponse } from '../interface/customhttpresponse';
import { CustomerData } from '../interface/customer';
import { Stats } from '../interface/stats';
import { User } from '../interface/user';

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
  customers$(page: number = 0, size: number = 10): Observable<CustomHttpResponse<CustomerData>> {
    return this.http.get<CustomHttpResponse<CustomerData>>(`${this.server}/customer/list?page=${page}&size=${size}`)
      .pipe(
        tap(console.log),
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
}
