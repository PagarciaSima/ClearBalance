import { EventReportStatus } from "../enum/event-report-status.enum";

export interface UserEventReportResponseDto {
  id: number;
  userEventId: number;
  reason: string | null;
  comment: string | null;
  createdAt: string;          // LocalDateTime → string ISO
  status: EventReportStatus;  // enum en TS

  device: string | null;
  ipAddress: string | null;
  eventType: string;
  eventDescription: string;
  eventCreatedAt: string;      // LocalDateTime → string ISO
}

export interface UserEventReportDetailDto {
  hasReport: boolean;
  report: UserEventReportResponseDto | null;
}