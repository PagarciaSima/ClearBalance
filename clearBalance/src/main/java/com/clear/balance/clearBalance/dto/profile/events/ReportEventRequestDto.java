package com.clear.balance.clearBalance.dto.profile.events;

import com.clear.balance.clearBalance.enumeration.EventReportStatus;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ReportEventRequestDto {
    
    @NotNull(message = "User event ID is required")
    private Long userEventId;
    
    private String reason;
    
    private String comment;
    
    private EventReportStatus status;
}