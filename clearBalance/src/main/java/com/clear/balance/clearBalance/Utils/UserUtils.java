package com.clear.balance.clearBalance.Utils;

import org.springframework.security.core.Authentication;

import com.clear.balance.clearBalance.domain.User;
import com.clear.balance.clearBalance.domain.UserPrincipal;
import com.clear.balance.clearBalance.dto.UserDto;
import com.clear.balance.clearBalance.dtoMapper.UserDtoMapper;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class UserUtils {

	public static UserDto getAuthenticatedUserDto(Authentication authentication) {
		User user = (User) authentication.getPrincipal();
		return UserDtoMapper.fromUser(user);
	}
	
    /**
     * Retrieves the authenticated user's {@link UserDto} from the given {@link Authentication} object.
     * <p>
     * If the {@link Authentication} principal is not an instance of {@link UserPrincipal} or is null,
     * this method returns {@code null}.
     *
     * @param authentication the {@link Authentication} object containing the authenticated principal
     * @return the {@link UserDto} of the authenticated user, or {@code null} if not available
     */
	public static UserDto getLoggedInUserDto(Authentication authentication) {
        if (authentication == null || authentication.getPrincipal() == null) {
            log.warn("Authentication or principal is null. Cannot retrieve UserDto.");
            return null;
        }

        Object principal = authentication.getPrincipal();

        if (principal instanceof UserPrincipal) {
            UserDto userDto = ((UserPrincipal) principal).getUser();
            log.debug("Retrieved UserDto for authenticated user: {}", userDto.getEmail());
            return userDto;
        } else {
            log.warn("Authentication principal is not an instance of UserPrincipal. Found: {}", principal.getClass().getName());
            return null;
        }
    }
}
