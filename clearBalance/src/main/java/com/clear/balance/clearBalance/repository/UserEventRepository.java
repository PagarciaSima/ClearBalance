package com.clear.balance.clearBalance.repository;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.clear.balance.clearBalance.domain.UserEvent;

@Repository
public interface UserEventRepository extends JpaRepository<UserEvent, Long> {
    List<UserEvent> findByUserId(Long userId);

    Page<UserEvent> findByUserId(Long userId, Pageable pageable);
    
}
