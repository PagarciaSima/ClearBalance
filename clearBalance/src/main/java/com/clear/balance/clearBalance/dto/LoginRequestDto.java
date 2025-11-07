package com.clear.balance.clearBalance.dto;

import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

@Data
public class LoginRequestDto {

	@NotEmpty
	private String email;
	@NotEmpty
	private String password;
}
