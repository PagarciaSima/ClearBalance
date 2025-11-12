package com.clear.balance.clearBalance.service;

import java.util.Collection;

import com.clear.balance.clearBalance.domain.User;
import com.clear.balance.clearBalance.dto.UserDto;

public interface UserService {
    /* Basic CRUD  */
	UserDto create(User data);
    Collection<User> list(int page, int pageSize);
    User get(Long id);
    User update(User data);
    Boolean delete(Long id);

    UserDto getUserDtoByEmail(String email);
	User getUserByEmail(String email);
	void sendVerificationCode(UserDto userDto);
	UserDto verifyCode(String email, String code);

}
