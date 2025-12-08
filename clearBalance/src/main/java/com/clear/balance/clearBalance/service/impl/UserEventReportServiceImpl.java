package com.clear.balance.clearBalance.service.impl;

import com.clear.balance.clearBalance.domain.events.UserEvent;
import com.clear.balance.clearBalance.domain.events.UserEventReport;
import com.clear.balance.clearBalance.dto.profile.events.ReportEventRequestDto;
import com.clear.balance.clearBalance.dto.profile.events.UpdateUserEventReportDto;
import com.clear.balance.clearBalance.dto.profile.events.UserEventReportResponseDto;
import com.clear.balance.clearBalance.enumeration.EventReportStatus;
import com.clear.balance.clearBalance.exeception.ApiException;
import com.clear.balance.clearBalance.repository.UserEventReportRepository;
import com.clear.balance.clearBalance.repository.UserEventRepository;
import com.clear.balance.clearBalance.service.UserEventReportService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserEventReportServiceImpl implements UserEventReportService {
    
    private final UserEventReportRepository userEventReportRepository;
    private final UserEventRepository userEventRepository;
    
    /**
     * Creates a new report for a specific {@link UserEvent}, submitted by the authenticated user.
     * <p>
     * This method performs several validation steps before creating the report:
     * <ul>
     *   <li>Ensures that the referenced {@link UserEvent} exists.</li>
     *   <li>Verifies that the event belongs to the authenticated user (ownership check).</li>
     *   <li>Checks that the event has not already been reported by the same user.</li>
     * </ul>
     * If all validations pass, a new {@link UserEventReport} is created with status
     * {@link EventReportStatus#PENDING} and persisted in the database.
     * </p>
     *
     * @param requestDto the request payload containing the event ID, report reason, and optional comment
     * @param userId the ID of the authenticated user submitting the report
     * @return a {@link UserEventReportResponseDto} containing the saved report's details
     *
     * @throws ApiException if the referenced user event does not exist
     * @throws IllegalArgumentException if the event does not belong to the user 
     *                                  or if the event was already reported by this user
     */
    @Override
    @Transactional
    public UserEventReportResponseDto reportEvent(ReportEventRequestDto requestDto, Long userId) {
        log.info("Creating report for user event ID: {} by user ID: {}", requestDto.getUserEventId(), userId);
        
        // Verify existence of UserEvent
        UserEvent userEvent = userEventRepository.findById(requestDto.getUserEventId())
                .orElseThrow(() -> new ApiException(
                        "User event not found with ID: " + requestDto.getUserEventId()));
        
        // verify ownership of the event
        if (!userEvent.getUser().getId().equals(userId)) {
            throw new IllegalArgumentException("This event does not belong to the authenticated user");
        }
        
        // verify if already reported
        boolean alreadyReported = userEventReportRepository.existsByUserEventIdAndUserId(
                requestDto.getUserEventId(), userId);
        
        if (alreadyReported) {
            throw new IllegalArgumentException("You have already reported this event");
        }
        
        // Create and save the report
        UserEventReport report = UserEventReport.builder()
                .userEvent(userEvent)
                .reason(requestDto.getReason())
                .comment(requestDto.getComment())
                .status(requestDto.getStatus())
                .build();
        
        UserEventReport savedReport = userEventReportRepository.save(report);
        
        log.info("Report created successfully with ID: {}", savedReport.getId());
        
        return mapToResponseDto(savedReport);
    }
    
    /**
     * Retrieves an existing report submitted by the user for a specific {@link UserEvent}.
     * <p>
     * If a report exists for the given user and event, it is transformed into a
     * {@link UserEventReportResponseDto}. Otherwise, an empty {@link Optional} is returned.
     * </p>
     *
     * @param userEventId the ID of the user event for which the report is requested
     * @param userId      the ID of the user who created the report
     * @return an {@link Optional} containing the report details if found, otherwise empty
     */
    @Override
    @Transactional(readOnly = true)
    public Optional<UserEventReportResponseDto> getReportForUserEvent(Long userEventId, Long userId) {
        log.info("Fetching report for user event ID: {} by user ID: {}", userEventId, userId);
        
        return userEventReportRepository.findByUserEventIdAndUserId(userEventId, userId)
                .map(this::mapToResponseDto);
    }
    
    /**
     * Updates an existing user event report with the provided fields.
     *
     * <p>This method retrieves the report by its ID and updates only the fields
     * that are present in the {@link UpdateUserEventReportDto}. Fields that are
     * {@code null} in the DTO are ignored, allowing for partial updates.
     * After applying the changes, the updated report is saved and mapped to a
     * {@link UserEventReportResponseDto}.</p>
     *
     * @param id  the ID of the report to update
     * @param dto the DTO containing the fields that should be updated
     * @return a {@link UserEventReportResponseDto} representing the updated report
     * @throws ApiException if no report exists with the given ID
     */
    @Override
    @Transactional
    public UserEventReportResponseDto updateReport(Long id, UpdateUserEventReportDto dto) {

        UserEventReport report = userEventReportRepository.findById(id)
                .orElseThrow(() -> new ApiException("Report not found with id: " + id));

        if (dto.getReason() != null) {
            report.setReason(dto.getReason());
        }

        if (dto.getComment() != null) {
            report.setComment(dto.getComment());
        }

        if (dto.getStatus() != null) {
            report.setStatus(dto.getStatus());
        }

        UserEventReport saved = userEventReportRepository.save(report);

        return mapToResponseDto(saved);
    } 
    
    private UserEventReportResponseDto mapToResponseDto(UserEventReport report) {
        UserEvent userEvent = report.getUserEvent();
        
        return UserEventReportResponseDto.builder()
                .id(report.getId())
                .userEventId(userEvent.getId())
                .reason(report.getReason())
                .comment(report.getComment())
                .createdAt(report.getCreatedAt())
                .status(report.getStatus())
                .device(userEvent.getDevice())
                .ipAddress(userEvent.getIpAddress())
                .eventType(userEvent.getEvent().getType().name())
                .eventDescription(userEvent.getEvent().getDescription())
                .eventCreatedAt(userEvent.getCreatedAt())
                .build();
    }
    
}