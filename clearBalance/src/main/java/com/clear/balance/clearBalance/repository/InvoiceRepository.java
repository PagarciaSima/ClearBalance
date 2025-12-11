package com.clear.balance.clearBalance.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.clear.balance.clearBalance.domain.invoice.Invoice;

public interface InvoiceRepository extends JpaRepository<Invoice, Long> {

}
