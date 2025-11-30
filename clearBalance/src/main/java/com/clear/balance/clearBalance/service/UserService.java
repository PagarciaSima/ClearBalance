package com.clear.balance.clearBalance.service;

import java.util.Collection;

import com.clear.balance.clearBalance.domain.User;
import com.clear.balance.clearBalance.dto.UpdateFormDto;
import com.clear.balance.clearBalance.dto.UpdatePasswordFormDto;
import com.clear.balance.clearBalance.dto.UserDto;

import jakarta.validation.Valid;

public interface UserService {
    /* Basic CRUD  */
	UserDto create(User data);
    Collection<User> list(int page, int pageSize);
    User getUserById(Long id);
    User update(User data);
    Boolean delete(Long id);

    UserDto getUserDtoByEmail(String email);
	User getUserByEmail(String email);
	void sendVerificationCode(UserDto userDto);
	UserDto verifyCode(String email, String code);
	UserDto resetPassword(String email);
	UserDto verifyPassword(String key);
	UserDto renewPassword(String key, String password, String confirmPassword);
	UserDto verifyAccount(String key);
	UserDto updateUserDetails(@Valid UpdateFormDto user);
	void updatePassword(Long id, @Valid UpdatePasswordFormDto updatePasswordFormDto);
	/**
	 * Retrieves a user along with their associated role information by user ID.
	 * <p>
	 * This method uses a {@code LEFT JOIN FETCH} query to eagerly fetch the {@link UserRole}
	 * and {@link Role} associated with the user, ensuring that all role data is available
	 * in a single query.
	 * <p>
	 * The method is marked as read-only transactional for optimal performance.
	 *
	 * @param userId the ID of the user to retrieve
	 * @return the {@link User} entity with its associated {@link UserRole} and {@link Role}
	 * @throws ApiException if no user is found with the specified ID
	 */
	User getUserWithRoleById(Long userId);
	void updateAccountSettings(Long id, Boolean enabled, Boolean notLocked);

}
