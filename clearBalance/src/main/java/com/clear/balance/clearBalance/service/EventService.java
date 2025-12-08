package com.clear.balance.clearBalance.service;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import com.clear.balance.clearBalance.dto.profile.events.UserEventResponseDto;
import com.clear.balance.clearBalance.enumeration.EventType;

public interface EventService {
	Page<UserEventResponseDto> getPagedEventsByUserId(Long userId, Pageable pageable);

	void addUserEvent(String email, EventType eventType, String device, String apiAddress);
	void addUserEvent(Long userId, EventType eventType, String device, String apiAddress);

}
