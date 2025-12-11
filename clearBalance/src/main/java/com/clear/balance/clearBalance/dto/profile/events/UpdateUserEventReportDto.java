package com.clear.balance.clearBalance.dto.profile.events;

import com.clear.balance.clearBalance.enumeration.EventReportStatus;

import lombok.Data;

@Data
public class UpdateUserEventReportDto {
    private String reason;
    private String comment;
    private EventReportStatus status;
}


