package com.clear.balance.clearBalance.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.clear.balance.clearBalance.domain.Role;

public interface RoleRepository extends JpaRepository<Role, Long>{

	Optional<Role> findByName(String string);

}
