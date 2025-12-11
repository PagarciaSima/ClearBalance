package com.clear.balance.clearBalance.service;

import org.springframework.data.domain.Page;

import com.clear.balance.clearBalance.domain.customer.Customer;
import com.clear.balance.clearBalance.domain.invoice.Invoice;

public interface CustomerService {
    // Customer functions
    Customer createCustomer(Customer customer);
    Customer updateCustomer(Customer customer);
    Page<Customer> getCustomers(int page, int size);
    Iterable<Customer> getCustomers();
    Customer getCustomer(Long id);
    Page<Customer> searchCustomers(String name, int page, int size);

    // Invoice functions
    Invoice createInvoice(Invoice invoice);
    Page<Invoice> getInvoices(int page, int size);
    void addInvoiceToCustomer(Long id, Invoice invoice);
	Invoice getInvoice(Long id);

}