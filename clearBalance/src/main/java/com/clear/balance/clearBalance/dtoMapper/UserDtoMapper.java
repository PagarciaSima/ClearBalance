package com.clear.balance.clearBalance.dtoMapper;

import org.springframework.beans.BeanUtils;

import com.clear.balance.clearBalance.domain.Role;
import com.clear.balance.clearBalance.domain.User;
import com.clear.balance.clearBalance.dto.UserDto;

public class UserDtoMapper {
    public static UserDto fromUser(User user) {
    	UserDto userDTO = new UserDto();
        BeanUtils.copyProperties(user, userDTO);
        return userDTO;
    }

    public static UserDto fromUser(User user, Role role) {
    	UserDto userDTO = new UserDto();
        BeanUtils.copyProperties(user, userDTO);
        userDTO.setRoleName(role.getName());
        userDTO.setPermissions(role.getPermission());
        return userDTO;
    }

    public static User toUser(UserDto userDTO) {
        User user = new User();
        BeanUtils.copyProperties(userDTO, user);
        return user;
    }
}