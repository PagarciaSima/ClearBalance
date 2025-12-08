package com.clear.balance.clearBalance.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.clear.balance.clearBalance.domain.events.Event;
import com.clear.balance.clearBalance.enumeration.EventType;

@Repository
public interface EventRepository extends JpaRepository<Event, Long> {
    Optional<Event> findByType(EventType type);
}