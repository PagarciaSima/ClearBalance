import { EventReportStatus } from "../enum/event-report-status.enum";

export interface ReportEventRequest {
  userEventId?: number;   
  reason?: string;      
  comment?: string;      
  status: EventReportStatus; 
}