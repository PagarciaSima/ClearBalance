package com.clear.balance.clearBalance.service.impl;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import com.clear.balance.clearBalance.enumeration.VerificationType;
import com.clear.balance.clearBalance.exeception.ApiException;
import com.clear.balance.clearBalance.service.EmailService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
@Service
public class EmailServiceImpl implements EmailService {

	private final JavaMailSender mailSender;
	@Value("${spring.mail.from}")
	private String from;

	/**
	 * Sends a verification email to the user.
	 * <p>
	 * Depending on the {@link VerificationType}, this method sends either an
	 * account verification email or a password reset email containing a
	 * verification link.
	 * </p>
	 *
	 * @param firstName        the recipient's first name
	 * @param email            the recipient's email address
	 * @param verificationUrl the verification URL to be included in the email
	 * @param verificationType the type of verification email to send
	 *
	 * @throws ApiException if the verification type is not supported
	 */
	@Override
	public void sendVerificationEmail(
	        String firstName,
	        String email,
	        String verificationUrl,
	        VerificationType verificationType
	) {
	    log.info("Preparing {} verification email for user {}", verificationType, email);

	    try {
	        SimpleMailMessage message = new SimpleMailMessage();
	        message.setFrom(from);
	        message.setTo(email);
	        message.setSubject(String.format(
	                "Clear Balance - %s Verification Email",
	                StringUtils.capitalize(verificationType.getType())
	        ));
	        message.setText(getEmailMessage(firstName, verificationUrl, verificationType));

	        mailSender.send(message);

	        log.info("Verification email of type {} successfully sent to {}", verificationType, email);
	    } catch (Exception exception) {
	        log.error(
	                "Failed to send {} verification email to {}",
	                verificationType,
	                email,
	                exception
	        );
	        throw new ApiException("Unable to send verification email");
	    }
	}

	/**
	 * Builds the email message body based on the verification type.
	 *
	 * @param firstName        the recipient's first name
	 * @param verificationUrl the verification URL to be included in the email
	 * @param verificationType the type of verification email
	 * @return the email message body as a {@link String}
	 *
	 * @throws ApiException if the verification type is not supported
	 */
	private String getEmailMessage(
	        String firstName,
	        String verificationUrl,
	        VerificationType verificationType
	) {
	    log.debug("Generating email content for verification type {}", verificationType);

	    return switch (verificationType) {
	        case PASSWORD -> "Hello " + firstName
	                + "\n\nReset password request. Please click the link below to reset your password."
	                + "\n\n" + verificationUrl
	                + "\n\nThe Support Team";

	        case ACCOUNT -> "Hello " + firstName
	                + "\n\nYour new account has been created. Please click the link below to verify your account."
	                + "\n\n" + verificationUrl
	                + "\n\nThe Support Team";

	        default -> {
	            log.error("Unsupported verification type: {}", verificationType);
	            throw new ApiException("Unable to send email. Email type unknown");
	        }
	    };
	}

}
