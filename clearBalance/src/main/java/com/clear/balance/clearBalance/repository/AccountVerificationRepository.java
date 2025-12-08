package com.clear.balance.clearBalance.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.clear.balance.clearBalance.domain.auth.AccountVerification;
import com.clear.balance.clearBalance.domain.user.User;

public interface AccountVerificationRepository extends JpaRepository<AccountVerification, Long> {
    Optional<AccountVerification> findByUrl(String url);
    Optional<AccountVerification> findByUser(User user);
    @Query("SELECT a FROM AccountVerification a WHERE a.url LIKE %:key%")
    Optional<AccountVerification> findByUrlContaining(@Param("key") String key);
}
