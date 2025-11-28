import { Injectable } from '@angular/core';
import {
  HttpRequest,
  HttpHandler,
  HttpEvent,
  HttpInterceptor,
  HttpErrorResponse
} from '@angular/common/http';
import { BehaviorSubject, catchError, Observable, switchMap, throwError, filter, take } from 'rxjs';
import { Key } from '../enum/key.enum';
import { UserService } from '../service/user.service';
import { CustomHttpResponse } from 'src/app/interface/customhttpresponse';
import { Profile } from 'src/app/interface/profile';

@Injectable({ providedIn: 'root' })
export class TokenInterceptor implements HttpInterceptor {
  private isTokenRefreshing: boolean = false;
  private refreshTokenSubject: BehaviorSubject<CustomHttpResponse<Profile> | null> =
    new BehaviorSubject<CustomHttpResponse<Profile> | null>(null);

  constructor(
    private userService: UserService
  ) {}

  /**
   * Intercepts HTTP requests to add an Authorization header with a Bearer token.
   * If the token is expired, it attempts to refresh the token and retry the request.
   * @param request - The outgoing HTTP request
   * @param next - The next interceptor in the chain
   * @returns An Observable of the HTTP event stream
   */
  intercept(request: HttpRequest<unknown>, next: HttpHandler): Observable<HttpEvent<unknown>> {
    if (this.isBypassUrl(request.url)) {
      return next.handle(request);
    }
    return next.handle(
      this.addAuthorizationTokenHeader(request, localStorage.getItem(Key.TOKEN))
    ).pipe(
      catchError((error: HttpErrorResponse) => {
        // Check if the error is due to an expired token
        if (this.isTokenExpiredError(error)) {
          return this.handleRefreshToken(request, next);
        }
        // For other errors, propagate the error
        else {
          return throwError(() => error);
        }
      })
    );
  }

  /** 
   * Adds an Authorization header with the Bearer token to the HTTP request 
   * @param request - The outgoing HTTP request
   * @param token - The JWT token to be added to the request header
   * @returns A cloned HTTP request with the Authorization header set
   */
  private addAuthorizationTokenHeader(request: HttpRequest<unknown>, token: string | null): HttpRequest<any> {
    if (!token) {
      return request;
    }
    
    return request.clone({
      setHeaders: {
        Authorization: `Bearer ${token}`
      }
    });
  }
  
  /** 
   * Handles the token refresh process when the access token has expired.
   * @param request - The original HTTP request that failed
   * @param next - The next interceptor in the chain
   * @returns An Observable of the HTTP event stream
   */
  private handleRefreshToken(request: HttpRequest<unknown>, next: HttpHandler): Observable<HttpEvent<unknown>> {
    if (!this.isTokenRefreshing) {
      return this.startTokenRefresh(request, next);
    } else {
      return this.waitForTokenRefresh(request, next);
    }
  }

  /**
   * Starts the token refresh process and retries the original request upon success.
   * @param request - The original HTTP request that failed
   * @param next - The next interceptor in the chain
   * @returns An Observable of the HTTP event stream
   */
  private startTokenRefresh(request: HttpRequest<unknown>, next: HttpHandler): Observable<HttpEvent<unknown>> {
    console.log('Refreshing Token...');
    this.isTokenRefreshing = true;
    this.refreshTokenSubject.next(null);
    const refreshToken = localStorage.getItem(Key.REFRESH_TOKEN);

    if (!refreshToken) {
      this.isTokenRefreshing = false;
      return throwError(() => new Error('No refresh token available'));
    }

    return this.userService.refreshToken$(refreshToken).pipe(
      switchMap((response: CustomHttpResponse<Profile>) => {
        console.log('Token Refresh Response:', response);
        this.isTokenRefreshing = false;
        this.refreshTokenSubject.next(null);

        if (response.data?.access_token) {
          localStorage.setItem(Key.TOKEN, response.data.access_token);
          this.refreshTokenSubject.next(response);
          console.log('New Token:', response.data.access_token);
          console.log('Sending original request:', request);
          return next.handle(this.addAuthorizationTokenHeader(request, response.data.access_token ?? null));
        } else {
          return throwError(() => new Error('No access token in response'));
        }
      }),
      catchError((error) => this.handleRefreshError(error))
    );
  }

  /**
   * Waits for the token refresh process to complete and retries the original request.
   * @param request - The original HTTP request that failed
   * @param next - The next interceptor in the chain
   * @returns An Observable of the HTTP event stream
   */
  private waitForTokenRefresh(request: HttpRequest<unknown>, next: HttpHandler): Observable<HttpEvent<unknown>> {
    return this.refreshTokenSubject.pipe(
      filter((response): response is CustomHttpResponse<Profile> => response !== null && response.data !== undefined && response.data.access_token !== undefined),
      take(1),
      switchMap((response) => {
        return next.handle(this.addAuthorizationTokenHeader(request, response.data?.access_token ?? null));
      })
    );
  }

  /**
   * Handles errors that occur during the token refresh process.
   * @param error - The error that occurred
   * @returns An Observable that errors with the provided error
   */
  private handleRefreshError(error: any): Observable<never> {
    this.isTokenRefreshing = false;
    console.error('Token refresh failed:', error);
    localStorage.removeItem(Key.TOKEN);
    localStorage.removeItem(Key.REFRESH_TOKEN);
    return throwError(() => error);
  }

  /** 
   * Determines if the given URL should bypass token interception.
   * @param url - The URL of the HTTP request
   * @returns A boolean indicating whether the URL should bypass token interception
   */
  private isBypassUrl(url: string): boolean {
    return (
      url.includes('verify') ||
      url.includes('login') ||
      url.includes('register') ||
      url.includes('refresh') ||
      url.includes('resetpassword')
    );
  }

  /** 
   * Determines if the error is due to an expired token.
   * @param error - The HTTP error response
   * @returns A boolean indicating whether the error is due to an expired token
   */
  private isTokenExpiredError(error: HttpErrorResponse): boolean {
    return (
      error instanceof HttpErrorResponse &&
      error.status === 401 &&
      error.error?.reason?.includes('expired')
    );
  }

}