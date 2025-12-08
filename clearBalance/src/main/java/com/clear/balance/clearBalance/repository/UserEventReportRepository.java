package com.clear.balance.clearBalance.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.clear.balance.clearBalance.domain.events.UserEventReport;
import com.clear.balance.clearBalance.enumeration.EventReportStatus;

@Repository
public interface UserEventReportRepository extends JpaRepository<UserEventReport, Long> {
        
    @Query("SELECT COUNT(ur) > 0 FROM UserEventReport ur WHERE ur.userEvent.id = :userEventId AND ur.userEvent.user.id = :userId")
    boolean existsByUserEventIdAndUserId(@Param("userEventId") Long userEventId, 
                                         @Param("userId") Long userId);
    
    @Query("SELECT ur FROM UserEventReport ur WHERE ur.userEvent.id = :userEventId AND ur.userEvent.user.id = :userId")
    Optional<UserEventReport> findByUserEventIdAndUserId(@Param("userEventId") Long userEventId, 
                                                         @Param("userId") Long userId);
    
    boolean existsByUserEventId(Long userEventId);

    @Query("SELECT ur.status FROM UserEventReport ur WHERE ur.userEvent.id = :userEventId")
    Optional<EventReportStatus> findStatusByUserEventId(@Param("userEventId") Long userEventId);
}