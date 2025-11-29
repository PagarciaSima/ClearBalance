import { HttpClient, HttpErrorResponse, HttpHeaders } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { catchError, Observable, tap, throwError } from 'rxjs';
import { CustomHttpResponse } from '../interface/customhttpresponse';
import { Profile } from '../interface/profile';
import { User } from '../interface/user';
import { Key } from '../enum/key.enum';
import { UpdatePasswordForm } from '../interface/updatePasswordForm';

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
   * Retrieves the profile information of the user from the server.
   * @returns An Observable emitting a CustomHttpResponse containing the user's Profile
   * 
   * @remarks
   * - Utilizes HttpClient to send a GET request to the server's /user/profile endpoint
   * - Pipes the response to log it and handle any potential errors using handleError method
   */
  profile$(): Observable<CustomHttpResponse<Profile>> {
    return this.http.get<CustomHttpResponse<Profile>>(
      `${this.server}/user/profile`
    )
      .pipe(
        tap(console.log),
        catchError(this.handleError)
      );
  }

  /**
   * Sends a request to update the user's profile information on the server.
   * @param user - The user object containing updated profile information
   * @returns An Observable emitting a CustomHttpResponse containing the updated user's Profile
   * 
   * @remarks
   * - Utilizes HttpClient to send a PATCH request to the server's /user/update endpoint
   * - Includes an Authorization header with a Bearer token for authentication
   * - Pipes the response to log it and handle any potential errors using handleError method
   */
  update$(user: User): Observable<CustomHttpResponse<Profile>> {
    const headers = new HttpHeaders()
      .set('Content-Type', 'application/json'); 

    return this.http.patch<CustomHttpResponse<Profile>>(
      `${this.server}/user/update`,
      user,
      { headers }
    ).pipe(
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
   * Requests a new refresh token from the backend using the current Authorization header.
   * @param token - The refresh token (Bearer ...)
   * @returns An Observable emitting a CustomHttpResponse with the new refresh token and user data
   * 
   * @remarks
   * - Utilizes HttpClient to send a GET request to the server's /user/refresh/token endpoint
   * - Includes an Authorization header with the refresh token for authentication
   * - Pipes the response to update localStorage with the new tokens and handle any potential errors using handleError method
   */
  refreshToken$(token: string): Observable<CustomHttpResponse<any>> {
    return this.http.get<CustomHttpResponse<any>>(
      `${this.server}/user/refresh/token`,
      { 
        headers: { 
          Authorization: `Bearer ${token}`  
        } 
      }
    ).pipe(
      tap(response => {
        console.log('Refresh Token Response:', response); 
        localStorage.removeItem(Key.TOKEN);
        localStorage.removeItem(Key.REFRESH_TOKEN);
        
        localStorage.setItem(Key.TOKEN, response.data.access_token);
        localStorage.setItem(Key.REFRESH_TOKEN, response.data.refresh_token);
      }),
      catchError(this.handleError)
    );
  }

  /**
   * Sends a request to update the user's password.
   * @param form - Object containing the current password, new password, and its confirmation
   * @returns An Observable emitting a CustomHttpResponse indicating the result of the operation
   * 
   * @remarks
   * - Utilizes HttpClient to send a PATCH request to /user/update/password
   * - Includes Content-Type: application/json header
   * - Pipes the response to log it and handle any potential errors using handleError method
   */
  updatePassword$(form: UpdatePasswordForm): Observable<CustomHttpResponse<any>> {
    const headers = new HttpHeaders()
      .set('Content-Type', 'application/json');

    return this.http.patch<CustomHttpResponse<any>>(
      `${this.server}/user/update/password`,
      form,
      { headers }
    ).pipe(
      tap(console.log),
      catchError(this.handleError)
    );
  }

}
