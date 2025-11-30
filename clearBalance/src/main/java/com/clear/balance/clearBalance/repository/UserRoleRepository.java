package com.clear.balance.clearBalance.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.clear.balance.clearBalance.domain.Role;
import com.clear.balance.clearBalance.domain.UserRole;

public interface UserRoleRepository extends JpaRepository<UserRole, Long> {

	@Query("SELECT ur.role FROM UserRole ur WHERE ur.user.id = :userId")
    Role findRoleByUserId(@Param("userId") Long userId);

	@Query("SELECT ur FROM UserRole ur WHERE ur.user.id = :userId")
	Optional<UserRole> findByUserId(@Param("userId") Long userId);
}