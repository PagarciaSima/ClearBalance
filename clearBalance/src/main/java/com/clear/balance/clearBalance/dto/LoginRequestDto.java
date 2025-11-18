package com.clear.balance.clearBalance.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

@Data
public class LoginRequestDto {

	@NotEmpty(message = "Email must not be empty")
	@Email(message = "Invalid email. Please provide a valid email address")
	private String email;
	@NotEmpty(message = "Password must not be empty")
	private String password;
}
