package com.clear.balance.clearBalance.service.impl;

import java.util.List;

import org.springframework.stereotype.Service;

import com.clear.balance.clearBalance.domain.Role;
import com.clear.balance.clearBalance.domain.UserRole;
import com.clear.balance.clearBalance.dto.RoleDto;
import com.clear.balance.clearBalance.exeception.ApiException;
import com.clear.balance.clearBalance.repository.RoleRepository;
import com.clear.balance.clearBalance.repository.UserRoleRepository;
import com.clear.balance.clearBalance.service.UserRoleService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Service
@Slf4j
public class UserRoleServiceImpl implements UserRoleService {

    private final UserRoleRepository userRoleRepository;
    private final RoleRepository roleRepository;

    /**
     * Retrieves the {@link Role} assigned to a specific user by their ID.
     * <p>
     * This method queries the {@link UserRoleRepository} to find the role associated
     * with the given user ID. If no role is found, it logs an error and throws an
     * {@link ApiException}.
     * </p>
     *
     * @param userId the ID of the user whose role is to be retrieved
     * @return the {@link Role} assigned to the user
     * @throws ApiException if no role is found for the given user ID
     */
    @Override
    public Role getRoleByUserId(Long userId) {
        log.info("Fetching role for user with ID: {}", userId);

        Role role = userRoleRepository.findRoleByUserId(userId);
        if (role == null) {
            log.error("No role assigned for user with ID: {}", userId);
            throw new ApiException("No role assigned for user with ID: " + userId);
        }

        log.info("Role '{}' retrieved for user ID: {}", role.getName(), userId);
        return role;
    }
    
    /**
     * Retrieves a {@link Role} by its unique name.
     * <p>
     * This method queries the {@link RoleRepository} to locate a role matching the
     * provided name. If no role is found, an {@link ApiException} is thrown.
     * </p>
     *
     * @param name the unique name of the role to retrieve
     * @return the {@link Role} matching the given name
     * @throws ApiException if no role exists with the specified name
     */
    @Override
    public Role findRoleByName(String name) {
        Role role = roleRepository.findByName(name)
                .orElseThrow(() -> new ApiException("Role " + name + " not found."));
        return role;
    }

    /**
     * Retrieves all available roles as DTOs.
     * <p>
     * This method queries the {@link RoleRepository} to fetch the full list of roles,
     * maps them to {@link RoleDto}, and returns the result. If no roles are found,
     * an {@link ApiException} is thrown.
     * </p>
     *
     * @return a list of {@link RoleDto} representing all system roles
     * @throws ApiException if no roles are found in the system
     */
    @Override
    public List<RoleDto> getAllRoles() {
        log.info("Fetching all roles");

        List<Role> roles = roleRepository.findAll();

        if (roles.isEmpty()) {
            log.error("No roles found in the system");
            throw new ApiException("No roles found in the system.");
        }

        List<RoleDto> roleDtos = roles.stream()
                .map(role -> new RoleDto(role.getId(), role.getName(), role.getPermission()))
                .toList();

        log.info("{} roles retrieved successfully", roleDtos.size());
        return roleDtos;
    }

    /**
     * Updates the role assigned to a specific user.
     * <p>
     * This method performs the following steps:
     * <ul>
     *     <li>Retrieves the target {@link Role} based on the provided role name.</li>
     *     <li>Fetches the existing {@link UserRole} entry associated with the given user ID.</li>
     *     <li>Updates the {@link UserRole} relationship with the new role.</li>
     *     <li>Saves the updated UserRole entity to persist the role change.</li>
     * </ul>
     * If the role does not exist or the user does not have a UserRole entry,
     * an {@link ApiException} is thrown.
     * </p>
     *
     * @param userId   the ID of the user whose role is being updated
     * @param roleName the name of the new role to assign to the user
     * @throws ApiException if the role is not found or the user has no associated UserRole entry
     */
    @Override
    public void updateUserRole(Long userId, String roleName) {
        log.info("Updating role for user ID: {} to '{}'", userId, roleName);

        // 1. Search for the new Role
        Role newRole = roleRepository.findByName(roleName)
                .orElseThrow(() -> {
                    log.error("Role '{}' not found", roleName);
                    return new ApiException("Role '" + roleName + "' not found.");
                });

        // 2. Get the related UserRole entry
        UserRole userRole = userRoleRepository.findByUserId(userId)
                .orElseThrow(() -> {
                    log.error("UserRole entry not found for user ID {}", userId);
                    return new ApiException("UserRole entry not found for user ID " + userId);
                });

        // 3. Update related Role
        userRole.setRole(newRole);

        // 4. Save the updated UserRole
        userRoleRepository.save(userRole);

        log.info("Role for user ID {} updated successfully to '{}'", userId, roleName);
    }

}

