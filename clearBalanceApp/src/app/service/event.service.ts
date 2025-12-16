import { Injectable } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { EventsPage } from '../interface/events';
import { catchError, Observable, tap, throwError } from 'rxjs';
import { CustomHttpResponse } from '../interface/customhttpresponse';
import { ReportEventRequest } from '../interface/reportEventRequest';
import { UserEventReportDetailDto, UserEventReportResponseDto } from '../interface/userEventReportResponse';

@Injectable({
  providedIn: 'root'
})
export class EventService {

  private readonly server: string = 'http://localhost:8080';
  constructor(
    private http: HttpClient
  ) { }

    /**
     * Retrieves a paginated list of user events from the server.
     */
    getUserEvents$(page: number = 0, size: number = 10): Observable<CustomHttpResponse<EventsPage>> {
      return this.http.get<CustomHttpResponse<EventsPage>>(
        `${this.server}/events/userevents?page=${page}&size=${size}`
      ).pipe(
        tap(response => console.log({response})),
        catchError(this.handleError)
      );
    }

    /**
     * Reports a suspicious user event.
     */
    reportEvent$(requestDto: ReportEventRequest): Observable<CustomHttpResponse<UserEventReportResponseDto>> {
      return this.http.post<CustomHttpResponse<UserEventReportResponseDto>>(`${this.server}/events/report`, requestDto)
        .pipe(catchError(this.handleError));
    }

    /**
     * Retrieves a specific event report for the authenticated user.
     */
    getEventReport$(eventId: number): Observable<CustomHttpResponse<UserEventReportDetailDto>> {
      return this.http.get<CustomHttpResponse<UserEventReportDetailDto>>(`${this.server}/events/${eventId}/report`)
        .pipe(catchError(this.handleError));
    }

    /**
     * Updates a user event report.
     */
    updateReport$(id: number, dto: ReportEventRequest): Observable<CustomHttpResponse<UserEventReportResponseDto>> {
      return this.http.patch<CustomHttpResponse<UserEventReportResponseDto>>(`${this.server}/events/reports/${id}`, dto)
        .pipe(catchError(this.handleError));
    }
  
    /**
     * Handles HTTP errors from service requests.
     */
    handleError(error: HttpErrorResponse): Observable<never> {
      return throwError(() => error);
    }
}
