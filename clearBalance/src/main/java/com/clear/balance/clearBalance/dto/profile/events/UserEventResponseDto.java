package com.clear.balance.clearBalance.dto.profile.events;

import java.time.LocalDateTime;

import com.clear.balance.clearBalance.enumeration.EventReportStatus;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserEventResponseDto {
    private Long id;
    private String type;
    private String description;
    private String device;
    private String ipAddress;
    private LocalDateTime createdAt;
    private boolean hasReport;   
    private EventReportStatus reportStatus;
}