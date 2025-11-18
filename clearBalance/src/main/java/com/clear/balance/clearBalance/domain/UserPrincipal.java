package com.clear.balance.clearBalance.domain;

import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.clear.balance.clearBalance.dto.UserDto;
import com.clear.balance.clearBalance.dtoMapper.UserDtoMapper;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class UserPrincipal implements UserDetails {

	private static final long serialVersionUID = 1907725179336300395L;
	
	private final User user;
	private final Role role;
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return Arrays.stream(this.role.getPermission().split(","))
	             .map(String::trim)
	             .map(SimpleGrantedAuthority::new)
	             .collect(Collectors.toList());
	}

	@Override
	public String getPassword() {
		return this.user.getPassword();
	}

	@Override
	public String getUsername() {
		return this.user.getEmail();
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return this.user.isNotLocked();
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return this.user.isEnabled();
	}
	
	public UserDto getUser() {
		return UserDtoMapper.fromUser(this.user, this.role);
	}
}
