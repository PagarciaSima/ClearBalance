import { HttpResponse } from '@angular/common/http';
import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class CacheService {

  private httpResponseCache: { [key: string]: HttpResponse<any> } = {};

  /**
   * Caches the given HTTP response under the specified key.
   * @param key The key to associate with the cached response
   * @param httpResponse The HTTP response to cache
   */
  put = (key: string, httpResponse: HttpResponse<any>): void => {
    console.log('Caching response', httpResponse);
    this.httpResponseCache[key] = httpResponse;
  }

  /**
   * Retrieves the cached HTTP response for the specified key.
   * @param key The key associated with the cached response
   * @returns The cached HTTP response, or undefined if not found
   */
  get = (key: string): HttpResponse<any> | undefined => this.httpResponseCache[key];

  /**
   * Deletes the cached HTTP response for the specified key.
   * @param key The key associated with the cached response to delete
   * @returns True if the entry was deleted, false otherwise
   */
  delete = (key: string): boolean => delete this.httpResponseCache[key];

  /**
   * Clears the entire cache of HTTP responses.
   */
  deleteAll = (): void => {
    console.log('Clearing entire cache');
    this.httpResponseCache = {};
  }

  /**
   * Logs the current state of the HTTP response cache to the console.
   */
  logCache = (): void => console.log(this.httpResponseCache);
}
