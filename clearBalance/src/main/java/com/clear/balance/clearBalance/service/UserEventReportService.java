package com.clear.balance.clearBalance.service;

import java.util.Optional;

import com.clear.balance.clearBalance.dto.profile.events.ReportEventRequestDto;
import com.clear.balance.clearBalance.dto.profile.events.UpdateUserEventReportDto;
import com.clear.balance.clearBalance.dto.profile.events.UserEventReportResponseDto;

public interface UserEventReportService {

	UserEventReportResponseDto reportEvent(ReportEventRequestDto requestDto, Long userId);
	Optional<UserEventReportResponseDto> getReportForUserEvent(Long userEventId, Long userId);
	UserEventReportResponseDto updateReport(Long id, UpdateUserEventReportDto dto);
}
