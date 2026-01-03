package com.clear.balance.clearBalance.service;

import java.util.List;

import org.springframework.data.domain.Page;

import com.clear.balance.clearBalance.domain.customer.Customer;
import com.clear.balance.clearBalance.domain.invoice.Invoice;
import com.clear.balance.clearBalance.dto.stats.StatsDto;

public interface CustomerService {
    // Customer functions
    Customer createCustomer(Customer customer);
    Customer updateCustomer(Customer customer);
    Page<Customer> getCustomers(int page, int size);
    Iterable<Customer> getCustomers();
    Customer getCustomer(Long id);
    Page<Customer> searchCustomers(String name, int page, int size);
	StatsDto getGlobalStats();

    // Invoice functions
    Invoice createInvoice(Invoice invoice);
    Page<Invoice> getInvoices(int page, int size);
    void addInvoiceToCustomer(Long id, Invoice invoice);
	Invoice getInvoice(Long id);
	List<Invoice> getAllInvoices();
	List<Customer> getAllCustomers();

}