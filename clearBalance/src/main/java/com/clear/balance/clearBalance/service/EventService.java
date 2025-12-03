package com.clear.balance.clearBalance.service;

import java.util.Collection;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import com.clear.balance.clearBalance.dto.UserEventResponseDto;
import com.clear.balance.clearBalance.enumeration.EventType;

public interface EventService {
	Collection<UserEventResponseDto> getEventsByUserId(Long userId);
	Page<UserEventResponseDto> getPagedEventsByUserId(Long userId, Pageable pageable);

	void addUserEvent(String email, EventType eventType, String device, String apiAddress);
	void addUserEvent(Long userId, EventType eventType, String device, String apiAddress);

}
