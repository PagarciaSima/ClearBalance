package com.clear.balance.clearBalance.service.impl;

import java.util.Date;

import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import com.clear.balance.clearBalance.domain.customer.Customer;
import com.clear.balance.clearBalance.domain.invoice.Invoice;
import com.clear.balance.clearBalance.domain.invoice.InvoiceService;
import com.clear.balance.clearBalance.dto.stats.StatsDto;
import com.clear.balance.clearBalance.exeception.ApiException;
import com.clear.balance.clearBalance.repository.CustomerRepository;
import com.clear.balance.clearBalance.repository.InvoiceRepository;
import com.clear.balance.clearBalance.service.CustomerService;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomerServiceImpl implements CustomerService {

    private final CustomerRepository customerRepository;
    private final InvoiceRepository invoiceRepository;

    /**
     * Creates a new customer in the system.
     *
     * <p>This method performs the following operations:
     * <ul>
     *   <li>Normalizes the customer's email (trimmed and lowercased)</li>
     *   <li>Validates that the email is not already in use</li>
     *   <li>Sets the creation timestamp</li>
     *   <li>Persists the customer entity in the database</li>
     * </ul>
     *
     * <p>If a customer with the same email already exists, an {@link ApiException}
     * is thrown to prevent duplicate records.</p>
     *
     * @param customer the customer entity to be created
     * @return the newly created and persisted {@link Customer}
     * @throws ApiException if a customer with the same email already exists
     */
    @Override
    public Customer createCustomer(Customer customer) {

        // Normalize email
        String normalizedEmail = customer.getEmail().trim().toLowerCase();
        customer.setEmail(normalizedEmail);

        // Verify if email already exists
        if (customerRepository.existsByEmail(normalizedEmail)) {
            log.warn("Attempt to create customer with existing email: {}", normalizedEmail);
            throw new ApiException("Email already in use. Please use a different email and try again.");
        }

        log.info("Creating new customer: {}", customer.getName());

        customer.setCreatedAt(new Date());
        Customer savedCustomer = customerRepository.save(customer);

        log.debug("Customer created with ID: {}", savedCustomer.getId());
        return savedCustomer;
    }

    /**
     * Updates an existing customer.
     *
     * @param customer the customer with updated fields
     * @return the updated customer
     */
    @Override
    public Customer updateCustomer(Customer customer) {
        log.info("Updating customer with ID: {}", customer.getId());
        Customer updatedCustomer = customerRepository.save(customer);
        log.debug("Customer updated: {}", updatedCustomer);
        return updatedCustomer;
    }

    /**
     * Retrieves a paginated list of customers.
     *
     * @param page page number (zero-based)
     * @param size number of records per page
     * @return paginated customers
     */
    @Override
    public Page<Customer> getCustomers(int page, int size) {
        log.info("Fetching customers - page: {}, size: {}", page, size);
        return customerRepository.findAll(PageRequest.of(page, size));
    }

    /**
     * Retrieves all customers.
     *
     * @return iterable list of all customers
     */
    @Override
    public Iterable<Customer> getCustomers() {
        log.info("Fetching all customers");
        return customerRepository.findAll();
    }

    /**
     * Retrieves a customer by ID.
     *
     * @param id customer ID
     * @return the customer, if found
     */
    @Override
    public Customer getCustomer(Long id) {
        log.info("Fetching customer with ID: {}", id);
        return customerRepository.findById(id)
                .orElseThrow(() -> {
                    log.warn("Customer with ID {} not found", id);
                    return new EntityNotFoundException("Customer not found");
                });
    }

    /**
     * Searches customers by name (case-insensitive).
     *
     * @param name customer name to search
     * @param page page number
     * @param size number of results per page
     * @return matching customers
     */
    @Override
    public Page<Customer> searchCustomers(String name, int page, int size) {
        log.info("Searching customers by name: '{}'", name);
        return customerRepository.findByNameContainingIgnoreCase(name, PageRequest.of(page, size));
    }

    /**
     * Creates a new invoice with a random invoice number.
     *
     * @param invoice invoice to create
     * @return created invoice
     */
    @Override
    public Invoice createInvoice(Invoice invoice) {
        log.info("Creating invoice for customer ID: {}", 
                 invoice.getCustomer() != null ? invoice.getCustomer().getId() : "null");

        invoice.setInvoiceNumber(RandomStringUtils.randomAlphanumeric(8).toUpperCase());
        Invoice savedInvoice = invoiceRepository.save(invoice);

        log.debug("Invoice created: {} for customer ID: {}", 
                  savedInvoice.getInvoiceNumber(),
                  savedInvoice.getCustomer() != null ? savedInvoice.getCustomer().getId() : "null");

        return savedInvoice;
    }

    /**
     * Retrieves paginated invoices.
     *
     * @param page page number
     * @param size page size
     * @return paginated invoices
     */
    @Override
    public Page<Invoice> getInvoices(int page, int size) {
        log.info("Fetching invoices - page: {}, size: {}", page, size);
        return invoiceRepository.findAll(PageRequest.of(page, size));
    }

    /**
     * Creates a new invoice and associates it with an existing customer.
     * <p>
     * This method performs the following steps:
     * <ul>
     *   <li>Retrieves the customer by its identifier.</li>
     *   <li>Generates a random invoice number.</li>
     *   <li>Associates the invoice with the customer.</li>
     *   <li>Associates each invoice service with the invoice.</li>
     *   <li>Calculates the total amount of the invoice based on its services.</li>
     *   <li>Persists the invoice and its services using cascade operations.</li>
     * </ul>
     *
     * @param customerId the identifier of the customer to whom the invoice will be added
     * @param invoice the invoice to be created and persisted
     * @throws EntityNotFoundException if the customer does not exist
     */
    @Override
    public void addInvoiceToCustomer(Long customerId, Invoice invoice) {

        log.info("Starting invoice creation for customerId={}", customerId);

        Customer customer = customerRepository.findById(customerId)
                .orElseThrow(() -> {
                    log.warn("Customer not found. customerId={}", customerId);
                    return new EntityNotFoundException("Customer not found");
                });

        log.debug("Customer resolved. customerId={}, customerName={}",
                customer.getId(), customer.getName());

        // Generate invoice number and associate customer
        String invoiceNumber = RandomStringUtils.randomAlphanumeric(8).toUpperCase();
        invoice.setInvoiceNumber(invoiceNumber);
        invoice.setCustomer(customer);

        log.debug("Invoice initialized. invoiceNumber={}, status={}, date={}",
                invoiceNumber, invoice.getStatus(), invoice.getDate());

        // Associate services with the invoice
        int serviceCount = 0;
        if (invoice.getServices() != null && !invoice.getServices().isEmpty()) {
            for (InvoiceService service : invoice.getServices()) {
                service.setInvoice(invoice);
                serviceCount++;
                log.trace("Service associated with invoice. description={}, price={}, quantity={}",
                        service.getDescription(), service.getPrice(), service.getQuantity());
            }
        } else {
            log.debug("Invoice has no services associated. invoiceNumber={}", invoiceNumber);
        }

        // Calculate total
        double total = invoice.getServices() == null ? 0.0 :
                invoice.getServices().stream()
                        .mapToDouble(s -> s.getPrice() * s.getQuantity())
                        .sum();

        invoice.setTotal(total);

        log.debug("Invoice total calculated. invoiceNumber={}, total={}, servicesCount={}",
                invoiceNumber, total, serviceCount);

        // Persist invoice
        invoiceRepository.save(invoice);

        log.info("Invoice successfully created. invoiceNumber={}, customerId={}",
                invoiceNumber, customerId);
    }


    /**
     * Retrieves an invoice by its unique ID.
     *
     * @param id the ID of the invoice to retrieve
     * @return the found {@link Invoice}
     * @throws ApiException if no invoice exists with the given ID
     */
    @Override
    public Invoice getInvoice(Long id) {
        log.debug("Fetching invoice with ID: {}", id);

        Invoice invoice = invoiceRepository.findById(id)
                .orElse(null);

        if (invoice == null) {
            log.warn("Invoice not found for ID: {}", id);
            throw new ApiException("Invoice not found with ID: " + id);
        }

        log.debug("Invoice found: {}", invoice);
        return invoice;
    }
    
    @Override
    public StatsDto getGlobalStats() {
    	int totalCustomers = (int) customerRepository.count();
        int totalInvoices = (int) invoiceRepository.count();
        double totalBilled = invoiceRepository.sumAllTotals(); 

        return new StatsDto(totalCustomers, totalInvoices, totalBilled);
	}

}
