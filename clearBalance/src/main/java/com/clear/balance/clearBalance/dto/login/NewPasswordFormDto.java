package com.clear.balance.clearBalance.dto.login;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class NewPasswordFormDto {
	@NotNull(message = "ID cannot be null or empty")
	private Long userId;

	@NotEmpty(message = "Password cannot be empty")
	private String password;

	@NotEmpty(message = "Confirm password cannot be empty")
	private String confirmPassword;
}
