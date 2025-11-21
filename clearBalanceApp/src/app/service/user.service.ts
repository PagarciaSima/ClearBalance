import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { catchError, Observable, tap, throwError } from 'rxjs';
import { CustomHttpResponse } from '../interface/customhttpresponse';
import { Profile } from '../interface/profile';

@Injectable({
  providedIn: 'root'
})
export class UserService {

  private readonly server: string = 'http://localhost:8080';
  constructor(
    private http: HttpClient
  ) { }

  /**
   * Sends a login request to the server with the provided email and password.
   * @param email - The user's email address
   * @param password - The user's password
   * @returns An Observable emitting a CustomHttpResponse containing the user's Profile on successful login
   * 
   * @remarks
   * - Utilizes HttpClient to send a POST request to the server's /user/login endpoint
   * - Pipes the response to log it and handle any potential errors using handleError method
   */
  login$(email: string, password: string): Observable<CustomHttpResponse<Profile>> {
    return this.http.post<CustomHttpResponse<Profile>>(`${this.server}/user/login`, { email, password })
      .pipe(
        tap(console.log),
        catchError(this.handleError)
      );
  }

  /**
   * Sends a verification code to the server to validate multi-factor authentication.
   * @param email - The user's email address
   * @param code - The verification code sent to the user
   * @returns An Observable emitting a CustomHttpResponse containing the user's Profile on successful verification
   * 
   * @remarks
   * - Utilizes HttpClient to send a GET request to the server's /user/verify-code/{email}/{code} endpoint
   * - Pipes the response to log it and handle any potential errors using handleError method
   */
  verifyCode$(email: string, code: string): Observable<CustomHttpResponse<Profile>> {
    return this.http.get<CustomHttpResponse<Profile>>(`${this.server}/user/verify/code/${email}/${code}`)
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
    let errorMessage: string;
    // Front end error
    if(error.error instanceof ErrorEvent) {
      errorMessage = `A client-side error occurred: ${error.error.message}`;
    }
    // Back end error
    else {
      if(error.error.reason) {
        errorMessage = error.error.reason;
      } else {
        errorMessage = `A server-side error occurred. Error status: ${error.status}, ` +
        `Error message: ${error.message}`;
      }
      
    }
    return throwError(() => errorMessage);
  }
}
