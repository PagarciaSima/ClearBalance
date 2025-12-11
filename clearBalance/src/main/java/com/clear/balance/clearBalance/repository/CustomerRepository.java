package com.clear.balance.clearBalance.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import com.clear.balance.clearBalance.domain.customer.Customer;

public interface CustomerRepository extends JpaRepository<Customer, Long> {

	Page<Customer> findByNameContainingIgnoreCase(String name, Pageable pagegeable);
}
