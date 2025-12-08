package com.clear.balance.clearBalance.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.clear.balance.clearBalance.domain.events.Event;
import com.clear.balance.clearBalance.domain.events.UserEvent;
import com.clear.balance.clearBalance.domain.user.User;
import com.clear.balance.clearBalance.dto.profile.events.UserEventResponseDto;
import com.clear.balance.clearBalance.enumeration.EventReportStatus;
import com.clear.balance.clearBalance.enumeration.EventType;
import com.clear.balance.clearBalance.repository.EventRepository;
import com.clear.balance.clearBalance.repository.UserEventReportRepository;
import com.clear.balance.clearBalance.repository.UserEventRepository;
import com.clear.balance.clearBalance.service.EventService;
import com.clear.balance.clearBalance.service.UserService;

import lombok.extern.slf4j.Slf4j;

@Service
@Transactional
@Slf4j
public class EventServiceImpl implements EventService {

    @Autowired
    private EventRepository eventRepository;

    @Autowired
    private UserEventRepository userEventRepository;

    @Autowired
    private UserService userService;
    
    @Autowired
    UserEventReportRepository userEventReportRepository;

	/**
	 * Retrieves a paginated list of user events associated with the specified user
	 * ID.
	 *
	 * @param userId   the ID of the user whose events should be retrieved
	 * @param pageable pagination information
	 * @return a paginated list of {@link UserEventResponseDto} representing the
	 *         user's event history
	 */	
    @Override
    public Page<UserEventResponseDto> getPagedEventsByUserId(Long userId, Pageable pageable) {
        log.info("Fetching paged events for user with ID: {}, page: {}", userId, pageable);

        Page<UserEventResponseDto> eventsPage = userEventRepository.findByUserId(userId, pageable)
        	    .map(ev -> {
        	        boolean hasReport = userEventReportRepository.existsByUserEventId(ev.getId());
        	        EventReportStatus status = userEventReportRepository.findStatusByUserEventId(ev.getId())
        	        		.orElse(null);

        	        return new UserEventResponseDto(
        	            ev.getId(),
        	            ev.getEvent().getType().name(),
        	            ev.getEvent().getDescription(),
        	            ev.getDevice(),
        	            ev.getIpAddress(),
        	            ev.getCreatedAt(),
        	            hasReport,
        	            status
        	        );
        	    });

        log.info("Successfully retrieved {} events for user ID: {} on page {}", eventsPage.getNumberOfElements(), userId, pageable.getPageNumber());
        return eventsPage;
    }

    /**
     * Creates a new {@link UserEvent} associated with a user identified by email.
     *
     * @param email     the email of the user
     * @param eventType the type of event to record
     * @param device    the device from which the event originated
     * @param ipAddress the IP address of the request
     */
    @Override
    public void addUserEvent(String email, EventType eventType, String device, String ipAddress) {
        log.info("Adding event '{}' for user with email: {}", eventType, email);
        User user = userService.getUserByEmail(email);
        addUserEvent(user.getId(), eventType, device, ipAddress);
    }

    /**
     * Creates and persists a new {@link UserEvent} for the user with the given ID.
     *
     * @param userId    the ID of the user
     * @param eventType the type of event to record
     * @param device    the device from which the event originated
     * @param ipAddress the IP address of the request
     */
    @Override
    public void addUserEvent(Long userId, EventType eventType, String device, String ipAddress) {

        log.info("Creating event '{}' for user with ID: {}", eventType, userId);

        // Fetch user
        User user = userService.getUserById(userId);
        log.debug("User loaded: {} ({})", user.getFullName(), user.getEmail());

        // Fetch event type definition
        Event event = eventRepository.findByType(eventType)
                .orElseThrow(() -> new RuntimeException("Event type not found: " + eventType));

        log.debug("Event type '{}' loaded successfully", eventType);

        // Create UserEvent
        UserEvent userEvent = UserEvent.builder()
                .user(user)
                .event(event)
                .device(device)
                .ipAddress(ipAddress)
                .build();

        // Persist
        userEventRepository.save(userEvent);

        log.info("UserEvent successfully created for user ID {} with event '{}'", userId, eventType);
    }
}
