package com.clear.balance.clearBalance.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.clear.balance.clearBalance.domain.User;

public interface UserRepository extends JpaRepository<User, Long>{
	 boolean existsByEmail(String email);
	 Optional<User> findByEmail(String email);
}
