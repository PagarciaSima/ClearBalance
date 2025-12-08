package com.clear.balance.clearBalance.dtoMapper;

import org.springframework.beans.BeanUtils;

import com.clear.balance.clearBalance.domain.role.Role;
import com.clear.balance.clearBalance.domain.user.User;
import com.clear.balance.clearBalance.dto.user.UserDto;

public class UserDtoMapper {
	
    public static UserDto fromUser(User user) {
    	UserDto userDTO = new UserDto();
        BeanUtils.copyProperties(user, userDTO);
        if (user.getUserRole() != null && user.getUserRole().getRole() != null) {
            Role role = user.getUserRole().getRole();
            userDTO.setRoleName(role.getName());
            userDTO.setPermissions(role.getPermission());
        }
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