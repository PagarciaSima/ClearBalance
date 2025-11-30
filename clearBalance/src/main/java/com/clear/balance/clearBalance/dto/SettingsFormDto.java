package com.clear.balance.clearBalance.dto;

import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class SettingsFormDto {
	@NotNull(message = "Enabled cannot be null or empty")
	private Boolean enabled;
	@NotNull(message = "Not Locked cannot be null or empty")
	private Boolean notLocked;
}
