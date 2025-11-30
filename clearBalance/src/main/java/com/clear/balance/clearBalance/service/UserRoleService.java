package com.clear.balance.clearBalance.service;

import java.util.List;

import com.clear.balance.clearBalance.domain.Role;
import com.clear.balance.clearBalance.dto.RoleDto;

public interface UserRoleService {

	Role getRoleByUserId(Long id);

	Role findRoleByName(String name);

	List<RoleDto> getAllRoles();

	void updateUserRole(Long id, String roleName);

}
