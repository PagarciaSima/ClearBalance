package com.clear.balance.clearBalance.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.clear.balance.clearBalance.domain.invoice.Invoice;

public interface InvoiceRepository extends JpaRepository<Invoice, Long> {
	@Query("SELECT COALESCE(SUM(i.total), 0) FROM Invoice i")
	double sumAllTotals();

}
