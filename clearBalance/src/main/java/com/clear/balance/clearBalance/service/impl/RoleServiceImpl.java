package com.clear.balance.clearBalance.service.impl;

import org.springframework.stereotype.Service;

import com.clear.balance.clearBalance.domain.Role;
import com.clear.balance.clearBalance.exeception.ApiException;
import com.clear.balance.clearBalance.repository.UserRoleRepository;
import com.clear.balance.clearBalance.service.RoleService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Service
@Slf4j
public class RoleServiceImpl implements RoleService {

    private final UserRoleRepository userRoleRepository;

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
}

