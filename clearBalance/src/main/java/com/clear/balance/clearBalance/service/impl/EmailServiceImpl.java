package com.clear.balance.clearBalance.service.impl;

import org.springframework.stereotype.Service;

import com.clear.balance.clearBalance.enumeration.VerificationType;
import com.clear.balance.clearBalance.service.EmailService;

@Service
public class EmailServiceImpl implements EmailService {

	@Override
	public void sendVerificationEmail(String firstName, String email, String verificationUrl,
			VerificationType verificationType) {
		// TODO Auto-generated method stub
		
	}

}
