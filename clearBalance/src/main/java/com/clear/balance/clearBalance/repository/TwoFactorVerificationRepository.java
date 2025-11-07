package com.clear.balance.clearBalance.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.clear.balance.clearBalance.domain.TwoFactorVerification;
import com.clear.balance.clearBalance.domain.User;

public interface TwoFactorVerificationRepository extends JpaRepository<TwoFactorVerification, Long> {
    void deleteByUserId(Long userId);

    TwoFactorVerification findByUserId(Long userId);

    TwoFactorVerification findByCode(String code);
}
