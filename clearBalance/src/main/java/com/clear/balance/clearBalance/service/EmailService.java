package com.clear.balance.clearBalance.service;

import com.clear.balance.clearBalance.enumeration.VerificationType;

public interface EmailService {
    void sendVerificationEmail(String firstName, String email, String verificationUrl, VerificationType verificationType);
}
