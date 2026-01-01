import { HttpClient, HttpErrorResponse, HttpHeaders } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { JwtHelperService } from '@auth0/angular-jwt';
import { BehaviorSubject, catchError, Observable, tap, throwError } from 'rxjs';
import { Key } from '../enum/key.enum';
import { CustomHttpResponse } from '../interface/customhttpresponse';
import { Profile } from '../interface/profile';
import { profileSettingsForm } from '../interface/profileSettingsForm';
import { UpdatePasswordForm } from '../interface/updatePasswordForm';
import { User } from '../interface/user';
import { AccountType } from '../interface/verifyState';

@Injectable()
export class UserService {

  private readonly server: string = 'http://localhost:8080';
  private readonly jwtHelper = new JwtHelperService();

  private profileSubject = new BehaviorSubject<Profile | null>(null);
  profile$Shared: Observable<Profile | null> = this.profileSubject.asObservable();

  constructor(private http: HttpClient) { }

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
   * Registers a new user by sending a POST request to the backend /register endpoint.
   * @param user The user object containing registration details.
   * @returns An Observable of the HTTP response containing the created user data.
   */
  registerUser$(user: User): Observable<CustomHttpResponse<Profile>> {
    return this.http.post<CustomHttpResponse<Profile>>(`${this.server}/user/register`, user);
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
   * Verifies the user's account or password reset using a provided key and type.
   * @param key - The verification key sent to the user
   * @param type - The type of verification (e.g., 'account' or 'password')
   * @returns An Observable emitting a CustomHttpResponse containing the user's Profile
   */
  verifyAccountOrPassword$(key: string, type: AccountType): Observable<CustomHttpResponse<Profile>> {
    return this.http.get<CustomHttpResponse<Profile>>(
      `${this.server}/user/verify/code/${type}/${key}`
    ).pipe(
      tap(console.log),
      catchError(this.handleError)
    );
  }

  /**
   * Sends a request to set a new password for the user.
   * @param form - Object containing the userId, new password, and its confirmation
   * @returns An Observable emitting a CustomHttpResponse indicating the result of the operation
   * 
   * @remarks
   * - Utilizes HttpClient to send a PUT request to /user/new/password
   * - Pipes the response to log it and handle any potential errors using handleError method
   */
  renewPassword$(form: {userId: number, password: string, confirmPassword: string}): Observable<CustomHttpResponse<Profile>> {
    return this.http.put<CustomHttpResponse<Profile>>(
      `${this.server}/user/new/password`, form
    ).pipe(
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
        tap(resp => {
          if (resp.data) {
            this.profileSubject.next(resp.data);
          }
        }),
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
      tap(resp => {
        if (resp.data) {
          this.profileSubject.next(resp.data);
        }
        console.log(resp);
      }),
      catchError(this.handleError)
    );
  }

  /**
   * Sends a password reset request to the backend for the given email address.
   * @param email - The user's email address to reset the password for.
   * @returns An Observable emitting a CustomHttpResponse with the backend's message.
   *
   * @remarks
   * - Utilizes HttpClient to send a GET request to the /user/resetpassword/{email} endpoint.
   * - Pipes the response to log it and handle any potential errors using handleError method.
   */
  requestPasswordReset$(email: string): Observable<CustomHttpResponse<Profile>> {
    return this.http.get<CustomHttpResponse<Profile>>(`${this.server}/user/resetpassword/${encodeURIComponent(email)}`)
      .pipe(
        tap(console.log),
        catchError(this.handleError)
      );
  }
  
  /**
   * Checks if the user is currently authenticated based on the presence and validity of the JWT token.
   * @returns A boolean indicating whether the user is authenticated (true) or not (false)
   */
  isAuthenticated(): boolean {
    const token = localStorage.getItem(Key.TOKEN);
    if (!token) return false;
    return !this.jwtHelper.isTokenExpired(token);
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
  refreshToken$(token: string): Observable<CustomHttpResponse<Profile>> {
    return this.http.get<CustomHttpResponse<Profile>>(
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

        localStorage.setItem(Key.TOKEN, response.data?.access_token || '');
        localStorage.setItem(Key.REFRESH_TOKEN, response.data?.refresh_token || '');
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
  updatePassword$(form: UpdatePasswordForm): Observable<CustomHttpResponse<Profile>> {
    const headers = new HttpHeaders()
      .set('Content-Type', 'application/json');

    return this.http.patch<CustomHttpResponse<Profile>>(
      `${this.server}/user/update/password`,
      form,
      { headers }
    ).pipe(
      tap(console.log),
      catchError(this.handleError)
    );
  }

  /**
   * Sends a request to update the user's role.
   * @param roleName - The new role name to be assigned to the user
   * @returns An Observable emitting a CustomHttpResponse containing the updated user's Profile
   * 
   * @remarks
   * - Utilizes HttpClient to send a PATCH request to /user/update/role/{roleName}
   * - Includes Content-Type: application/json header
   * - Pipes the response to log it and handle any potential errors using handleError method
   */
  updateRole$(roleName: string): Observable<CustomHttpResponse<Profile>> {
    const headers = new HttpHeaders()
      .set('Content-Type', 'application/json');

    return this.http.patch<CustomHttpResponse<Profile>>(
      `${this.server}/user/update/role/${roleName}`,
      {},
      { headers }
    ).pipe(
      tap(console.log),
      catchError(this.handleError)
    );
  }

  /**
   * Sends a request to update the user's profile settings.
   * @param form - Object containing the profile settings to be updated
   * @returns An Observable emitting a CustomHttpResponse containing the updated user's Profile
   * 
   * @remarks
   * - Utilizes HttpClient to send a PATCH request to /user/update/settings
   * - Includes Content-Type: application/json header
   * - Pipes the response to log it and handle any potential errors using handleError method
   */
  updateSettings$(form: profileSettingsForm): Observable<CustomHttpResponse<Profile>> {
    const headers = new HttpHeaders()
      .set('Content-Type', 'application/json');

    return this.http.patch<CustomHttpResponse<Profile>>(
      `${this.server}/user/update/settings`,
      form,
      { headers }
    ).pipe(
      tap(console.log),
      catchError(this.handleError)
    );
  }

  /**
   * Sends a request to toggle multi-factor authentication (MFA) for the user.
   * @returns An Observable emitting a CustomHttpResponse containing the updated user's Profile
   * 
   * @remarks
   * - Utilizes HttpClient to send a PATCH request to /user/togglemfa
   * - Includes Content-Type: application/json header
   * - Pipes the response to log it and handle any potential errors using handleError method
   */
  toggleMfa$(): Observable<CustomHttpResponse<Profile>> {
    const headers = new HttpHeaders()
      .set('Content-Type', 'application/json');

    return this.http.patch<CustomHttpResponse<Profile>>(
      `${this.server}/user/togglemfa`,
      {},
      { headers }
    ).pipe(
      tap(console.log),
      catchError(this.handleError)
    );
  }

  /**
   * Sends a request to update the user's profile image.
   * @param formData - FormData object containing the new profile image file
   * @returns An Observable emitting a CustomHttpResponse containing the updated user's Profile
   * 
   * @remarks
   * - Utilizes HttpClient to send a PATCH request to /user/update/image
   * - Pipes the response to log it and handle any potential errors using handleError method
   */
  updateImage$(formData: FormData): Observable<CustomHttpResponse<Profile>> {
    return this.http.patch<CustomHttpResponse<Profile>>(
      `${this.server}/user/update/image`,
      formData,
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

}