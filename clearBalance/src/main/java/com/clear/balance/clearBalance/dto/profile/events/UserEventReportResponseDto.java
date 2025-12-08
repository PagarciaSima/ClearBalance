package com.clear.balance.clearBalance.dto.profile.events;

import java.time.LocalDateTime;

import com.clear.balance.clearBalance.enumeration.EventReportStatus;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserEventReportResponseDto {
    private Long id;
    private Long userEventId;
    private String reason;
    private String comment;
    private LocalDateTime createdAt;
    private EventReportStatus status;
    
    private String device;
    private String ipAddress;
    private String eventType;
    private String eventDescription;
    private LocalDateTime eventCreatedAt;
}
