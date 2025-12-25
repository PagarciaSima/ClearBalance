import { Injectable } from '@angular/core';
import {
  HttpRequest,
  HttpHandler,
  HttpEvent,
  HttpInterceptor,
  HttpResponse
} from '@angular/common/http';
import { Observable, of } from 'rxjs';
import { filter, tap } from 'rxjs/operators';
import { CacheService } from '../service/cache.service';

@Injectable()
export class CacheInterceptor implements HttpInterceptor {

  constructor(private cacheService: CacheService) { }

  /**
   * Intercepts HTTP requests to implement caching logic.
   * Bypasses caching for authentication-related endpoints and non-GET requests.
   * Clears the cache on non-GET requests to ensure data consistency.
   *
   * @param req The outgoing HTTP request
   * @param next The next interceptor in the chain
   * @returns An Observable of the HTTP event stream
   */
  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    // Bypass caching for authentication-related endpoints
    if (req.url.includes('verify') || req.url.includes('login') || req.url.includes('register')
        || req.url.includes('refresh') || req.url.includes('resetpassword')) {
      return next.handle(req);
    }
    // Clear cache for non-GET requests
    if (req.method !== 'GET' || req.url.includes('download')) {
      this.cacheService.deleteAll();
      return next.handle(req);
    }

    // Check for cached response for GET requests
    const cachedResponse = this.cacheService.get(req.url);

    if (cachedResponse !== undefined) {
      console.log('Found Response in Cache', cachedResponse);
      this.cacheService.logCache();
      return of(cachedResponse);
    }

    // Proceed with request and cache the response
    return this.handleRequestCache(req, next);
  }

  /**
   * Handles the HTTP request and caches the response.
   *
   * @param request The outgoing HTTP request
   * @param next The next interceptor in the chain
   * @returns An Observable of the HTTP event stream
   */
  private handleRequestCache(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    return next.handle(request).pipe(
      filter((event: HttpEvent<any>): event is HttpResponse<any> => event instanceof HttpResponse),
      tap((response: HttpResponse<any>) => {
        // Cache only GET / PUT / POST responses
        if (request.method !== 'DELETE') {
          console.log('Caching Response', response);
          this.cacheService.put(request.url, response);
        }
      })
    );
  }
}
