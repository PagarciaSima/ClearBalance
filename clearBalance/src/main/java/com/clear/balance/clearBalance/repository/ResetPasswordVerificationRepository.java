package com.clear.balance.clearBalance.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.clear.balance.clearBalance.domain.ResetPasswordVerification;

@Repository
public interface ResetPasswordVerificationRepository extends JpaRepository<ResetPasswordVerification, Long> {
    
    
    Optional<ResetPasswordVerification> findByUserId(Long userId);
    
    @Modifying
    @Query("DELETE FROM ResetPasswordVerification r WHERE r.user.id = :userId")
    void deleteByUserId(@Param("userId") Long userId);
    
    @Modifying
    @Query("DELETE FROM ResetPasswordVerification r WHERE r.expirationDate < CURRENT_TIMESTAMP")
    void deleteAllExpired();

    @Query("SELECT r FROM ResetPasswordVerification r WHERE r.url LIKE %:key%")
    Optional<ResetPasswordVerification> findByUrlContaining(@Param("key") String key);
}