package com.clear.balance.clearBalance.listener;

import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import com.clear.balance.clearBalance.Utils.RequestUtils;
import com.clear.balance.clearBalance.event.NewUserEvent;
import com.clear.balance.clearBalance.service.EventService;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class NewUserEventListener {
    private final EventService eventService;
    private final HttpServletRequest request;

    @EventListener
    public void onNewUserEvent(NewUserEvent event) {
    	log.info("New user event received for email: {}.\n event type {}", event.getEmail(), event.getType());
        eventService.addUserEvent(
        		event.getEmail(), event.getType(), RequestUtils.getDevice(request), RequestUtils.getIpAddress(request)
        );
    }
}
