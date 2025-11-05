package com.clear.balance.clearBalance.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.clear.balance.clearBalance.domain.AccountVerification;
import com.clear.balance.clearBalance.domain.User;

public interface AccountVerificationRepository extends JpaRepository<AccountVerification, Long> {
    Optional<AccountVerification> findByUrl(String url);
    Optional<AccountVerification> findByUser(User user);
}
