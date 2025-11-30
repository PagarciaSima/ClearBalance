package com.clear.balance.clearBalance.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.clear.balance.clearBalance.domain.User;

public interface UserRepository extends JpaRepository<User, Long> {
	boolean existsByEmail(String email);

	Optional<User> findByEmail(String email);

	@Query("SELECT u FROM User u LEFT JOIN FETCH u.userRole ur LEFT JOIN FETCH ur.role WHERE u.id = :userId")
	Optional<User> findByIdWithUserRoleAndRole(@Param("userId") Long userId);
}
