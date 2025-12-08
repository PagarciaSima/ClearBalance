package com.clear.balance.clearBalance.service;

import java.util.List;

import com.clear.balance.clearBalance.domain.role.Role;
import com.clear.balance.clearBalance.dto.role.RoleDto;

public interface UserRoleService {

	Role getRoleByUserId(Long id);

	Role findRoleByName(String name);

	List<RoleDto> getAllRoles();

	void updateUserRole(Long id, String roleName);

}
