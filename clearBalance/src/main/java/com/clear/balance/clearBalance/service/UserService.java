package com.clear.balance.clearBalance.service;

import java.util.Collection;

import org.springframework.web.multipart.MultipartFile;

import com.clear.balance.clearBalance.domain.user.User;
import com.clear.balance.clearBalance.dto.profile.UpdatePasswordFormDto;
import com.clear.balance.clearBalance.dto.profile.UpdateProfileFormDto;
import com.clear.balance.clearBalance.dto.user.UserDto;

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
	UserDto updateUserDetails(@Valid UpdateProfileFormDto user);
	void updatePassword(Long id, @Valid UpdatePasswordFormDto updatePasswordFormDto);
	User getUserWithRoleById(Long userId);
	void updateAccountSettings(Long id, Boolean enabled, Boolean notLocked);
	UserDto toggleMfa(String email);
	UserDto updateImage(UserDto userDto, MultipartFile image);

}
