import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { catchError, Observable, tap, throwError } from 'rxjs';
import { CustomHttpResponse } from '../interface/customhttpresponse';
import { EventsPage } from '../interface/events';
import { ReportEventRequest } from '../interface/reportEventRequest';
import { UserEventReportDetailDto, UserEventReportResponseDto } from '../interface/userEventReportResponse';
import { environment } from 'src/environments/environment.prod';

@Injectable()
export class EventService {

  private readonly server: string = environment.API_BASE_URL;
  constructor(
    private http: HttpClient
  ) { }

    /**
     * Retrieves a paginated list of user events from the server.
     * @param page - Page number to retrieve  
     * @param size - Number of items per page
     */
    getUserEvents$(page: number = 0, size: number = 10): Observable<CustomHttpResponse<EventsPage>> {
      return this.http.get<CustomHttpResponse<EventsPage>>(
        `${this.server}/events/userevents?page=${page}&size=${size}`
      ).pipe(
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
