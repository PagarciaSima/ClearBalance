package com.clear.balance.clearBalance.service.impl;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.clear.balance.clearBalance.domain.Role;
import com.clear.balance.clearBalance.domain.User;
import com.clear.balance.clearBalance.domain.UserPrincipal;
import com.clear.balance.clearBalance.repository.UserRepository;
import com.clear.balance.clearBalance.repository.UserRoleRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomUserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.error("User not found in the database: {}", email);
                    return new UsernameNotFoundException("User not found in the database");
                });

        log.info("User found in the database: {}", email);

        Role role = userRoleRepository.findRoleByUserId(user.getId());
        if (role == null) {
            log.warn("User {} has no assigned role", email);
            throw new UsernameNotFoundException("User has no assigned role");
        }

        return new UserPrincipal(user, role.getPermission());
    }


}
