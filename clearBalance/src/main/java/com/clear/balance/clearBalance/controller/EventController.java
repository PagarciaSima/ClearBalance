package com.clear.balance.clearBalance.controller;

import java.time.LocalDateTime;
import java.util.Map;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.clear.balance.clearBalance.Utils.UserUtils;
import com.clear.balance.clearBalance.domain.response.HttpResponse;
import com.clear.balance.clearBalance.dto.profile.events.ReportEventRequestDto;
import com.clear.balance.clearBalance.dto.profile.events.UpdateUserEventReportDto;
import com.clear.balance.clearBalance.dto.profile.events.UserEventReportResponseDto;
import com.clear.balance.clearBalance.dto.profile.events.UserEventResponseDto;
import com.clear.balance.clearBalance.dto.user.UserDto;
import com.clear.balance.clearBalance.service.EventService;
import com.clear.balance.clearBalance.service.UserEventReportService;

import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Controller for handling event-related endpoints.
 */
@RestController
@RequestMapping("/events")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Events", description = "API for managing events")
public class EventController {

	private final EventService eventService;
	private final UserEventReportService userEventReportService;
	
	 /**
     * Retrieves a paginated list of events associated with the authenticated user.
     *
     * <p>This endpoint allows the client to request user-specific events using pagination
     * parameters. The events are sorted in descending order by their creation timestamp.
     * The authenticated user's identity is resolved through the provided {@link Authentication}
     * object.</p>
     *
     * @param authentication the authentication object containing the currently authenticated user
     * @param page the page number to retrieve (0-based index); defaults to {@code 0}
     * @param size the number of records per page; defaults to {@code 10}
     *
     * @return a {@link ResponseEntity} containing an {@link HttpResponse} with a paginated list
     *         of {@link UserEventResponseDto} objects under the {@code "events"} key
     *
     * @apiNote The response includes metadata such as total pages, total elements, and flags
     *          indicating whether the current page is the first or last page.
     *
     * @see UserUtils#getAuthenticatedUserDto(Authentication)
     * @see org.springframework.data.domain.Page
     * @see UserEventResponseDto
     */
    @GetMapping("/userevents")
    public ResponseEntity<HttpResponse> getUserEvents(
            Authentication authentication,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size
    ) {
        UserDto userDto = UserUtils.getAuthenticatedUserDto(authentication);
        log.info("Fetching events for user: {}, page: {}, size: {}", userDto.getId(), page, size);
        
        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        Page<UserEventResponseDto> eventsPage = this.eventService.getPagedEventsByUserId(userDto.getId(), pageable);

        HttpResponse response = HttpResponse.builder()
                .timeStamp(LocalDateTime.now().toString())
                .data(Map.of("events", eventsPage))
                .message("Events retrieved successfully")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build();

        return ResponseEntity.ok().body(response);
    }
    
    /**
     * Reports a suspicious user event.
     * <p>
     * This endpoint allows an authenticated user to report a specific event from their activity log
     * as suspicious. The user must own the event they are trying to report, and each event can
     * only be reported once by the same user.
     * </p>
     *
     * @param requestDto the request containing the event ID, reason, and optional comment
     * @param authentication the authentication object containing the current user
     * @return a {@link ResponseEntity} containing the created report details
     * @throws IllegalArgumentException if the event doesn't belong to the user or was already reported
     */
    @PostMapping("/report")
    public ResponseEntity<HttpResponse> reportEvent(
            @Valid @RequestBody ReportEventRequestDto requestDto,
            Authentication authentication) {
        
        UserDto userDto = UserUtils.getAuthenticatedUserDto(authentication);
        log.info("User {} reporting event ID: {}", userDto.getId(), userDto.getId());
        
        UserEventReportResponseDto responseDto = userEventReportService.reportEvent(requestDto, userDto.getId());
        
        HttpResponse response = HttpResponse.builder()
                .timeStamp(LocalDateTime.now().toString())
                .data(Map.of("report", responseDto))
                .message("Event reported successfully")
                .status(HttpStatus.CREATED)
                .statusCode(HttpStatus.CREATED.value())
                .build();
        
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
    
    /**
     * Retrieves a specific event report for the authenticated user.
     * <p>
     * This endpoint returns the report details if the user has previously reported the specified event.
     * If no report exists for this event and user, the response will contain null for the report field.
     * </p>
     *
     * @param eventId the ID of the user event
     * @param authentication the authentication object containing the current user
     * @return a {@link ResponseEntity} containing the report if it exists, otherwise null
     */
    @GetMapping("/{eventId}/report")
    public ResponseEntity<HttpResponse> getEventReport(
            @PathVariable Long eventId,
            Authentication authentication) {
        
        UserDto userDto = UserUtils.getAuthenticatedUserDto(authentication);
        log.info("User {} fetching report for event ID: {}", userDto.getId(), eventId);
        
        var report = userEventReportService.getReportForUserEvent(eventId, userDto.getId());
        
        Map<String, Object> responseData = Map.of(
            "hasReport", report.isPresent(),
            "report", report.orElse(null)
        );
        
        HttpResponse response = HttpResponse.builder()
                .timeStamp(LocalDateTime.now().toString())
                .data(responseData)
                .message(report.isPresent() ? "Report found" : "No report found for this event")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build();
        
        return ResponseEntity.ok().body(response);
    }
    
    /**
     * Updates an existing user event report.
     *
     * <p>This endpoint receives the report ID and the updated data in the request body.
     * It delegates the update operation to the service layer and returns the updated
     * report wrapped in a standardized {@link HttpResponse}.</p>
     *
     * @param id  the ID of the report to be updated
     * @param dto the payload containing the fields to update in the report
     * @return a {@link ResponseEntity} containing the updated report and a success message
     */
    @PatchMapping("/reports/{id}")
    public ResponseEntity<HttpResponse> updateReport(
            @PathVariable Long id,
            @RequestBody UpdateUserEventReportDto dto
    ) {
    	UserEventReportResponseDto updated = userEventReportService.updateReport(id, dto);

        HttpResponse response = HttpResponse.builder()
                .data(Map.of("report", updated))
                .message("Report updated successfully")
                .build();

        return ResponseEntity.ok(response);
    }

}
