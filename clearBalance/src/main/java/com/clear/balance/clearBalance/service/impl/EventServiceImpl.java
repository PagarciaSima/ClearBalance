package com.clear.balance.clearBalance.service.impl;

import java.util.Collection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.clear.balance.clearBalance.domain.Event;
import com.clear.balance.clearBalance.domain.User;
import com.clear.balance.clearBalance.domain.UserEvent;
import com.clear.balance.clearBalance.dto.UserEventResponseDto;
import com.clear.balance.clearBalance.enumeration.EventType;
import com.clear.balance.clearBalance.repository.EventRepository;
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

    /**
     * Retrieves all user events associated with the specified user ID.
     * <p>
     * This method fetches all {@link UserEvent} records for the given user,
     * converts them into lightweight {@link UserEventResponseDto} objects,
     * and returns the resulting collection. This ensures that no JPA entities
     * are exposed directly to the API layer, preventing serialization issues
     * such as infinite recursion.
     * </p>
     *
     * @param userId the ID of the user whose events should be retrieved
     * @return a collection of {@link UserEventResponseDto} representing the user's event history
     */
    @Override
    public Collection<UserEventResponseDto> getEventsByUserId(Long userId) {
        log.info("Fetching events for user with ID: {}", userId);

        Collection<UserEventResponseDto> events = userEventRepository.findByUserId(userId).stream()
                .map(ev -> {
                    log.debug("Mapping UserEvent (ID: {}) to UserEventResponseDto", ev.getId());
                    return new UserEventResponseDto(
                            ev.getId(),
                            ev.getEvent().getType().name(),
                            ev.getEvent().getDescription(),
                            ev.getDevice(),
                            ev.getIpAddress(),
                            ev.getCreatedAt()
                    );
                })
                .toList();

        log.info("Successfully retrieved {} events for user ID: {}", events.size(), userId);
        return events;
    }
    
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

        Page<UserEventResponseDto> events = userEventRepository.findByUserId(userId, pageable)
            .map(ev -> new UserEventResponseDto(
                ev.getId(),
                ev.getEvent().getType().name(),
                ev.getEvent().getDescription(),
                ev.getDevice(),
                ev.getIpAddress(),
                ev.getCreatedAt()
            ));

        log.info("Successfully retrieved {} events for user ID: {} on page {}", events.getNumberOfElements(), userId, pageable.getPageNumber());
        return events;
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
