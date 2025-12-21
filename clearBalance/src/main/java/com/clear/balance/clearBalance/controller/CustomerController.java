package com.clear.balance.clearBalance.controller;

import static org.springframework.web.servlet.support.ServletUriComponentsBuilder.fromCurrentContextPath;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Map;

import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.clear.balance.clearBalance.Utils.UserUtils;
import com.clear.balance.clearBalance.domain.customer.Customer;
import com.clear.balance.clearBalance.domain.invoice.Invoice;
import com.clear.balance.clearBalance.domain.response.HttpResponse;
import com.clear.balance.clearBalance.domain.user.User;
import com.clear.balance.clearBalance.dto.stats.StatsDto;
import com.clear.balance.clearBalance.dto.user.UserDto;
import com.clear.balance.clearBalance.service.CustomerService;
import com.clear.balance.clearBalance.service.UserService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * REST controller for managing customer-related operations.
 */
@RestController
@RequestMapping("/customer")
@RequiredArgsConstructor
@Slf4j
public class CustomerController {
	
	private final CustomerService customerService;
	private final UserService userService;

	/**
	 * Retrieves a paginated list of customers along with the authenticated user's information.
	 *
	 * <p>This endpoint extracts the authenticated user from the provided {@link Authentication}
	 * object, converts it into a {@link UserDto}, and then retrieves a paginated list of customers.
	 * The response contains both the requesting user's data and the paginated customer list.</p>
	 *
	 * @param authentication the authentication context containing the authenticated user's principal
	 * @param page the page index to retrieve (default is 0)
	 * @param size the number of customer records per page (default is 10)
	 * @return a {@link ResponseEntity} containing a {@link HttpResponse} with the authenticated user
	 *         and the paginated list of customers
	 */
	@GetMapping("/list")
	public ResponseEntity<HttpResponse> getCustomers(
	        final Authentication authentication,
	        @RequestParam(defaultValue = "0") int page,
	        @RequestParam(defaultValue = "10") int size
	) {
	    final UserDto user = userService.getUserDtoByEmail(UserUtils.getAuthenticatedUserDto(authentication).getEmail());
	    log.debug("User retrieved from service: {}", user);
	    log.info("Received request to retrieve customers (page={}, size={}) by user {}", page, size, user.getEmail());

	    var customersPage = customerService.getCustomers(page, size);
	    log.debug("Retrieved {} customers", customersPage.getNumberOfElements());

	    HttpResponse response = HttpResponse.builder()
	            .timeStamp(LocalDateTime.now().toString())
	            .data(
	                Map.of(
	                    "user", user,
	                    "customers", customersPage
	                )
	            )
	            .message("Customers retrieved")
	            .status(HttpStatus.OK)
	            .statusCode(HttpStatus.OK.value())
	            .build();

	    log.info("Customers successfully returned for user {}", user.getEmail());
	    return ResponseEntity.ok().body(response);
	}
	
	/**
	 * Retrieves global application statistics for dashboard purposes.
	 *
	 * <p>This endpoint returns aggregated, system-wide statistics including:
	 * <ul>
	 *   <li>Total number of customers</li>
	 *   <li>Total number of invoices</li>
	 *   <li>Total amount billed across all invoices</li>
	 * </ul>
	 *
	 * <p>The response also includes the authenticated user's information,
	 * allowing the frontend to display both user context and dashboard data
	 * in a single request.</p>
	 *
	 * <p>This endpoint is typically used to populate a global dashboard
	 * or overview screen.</p>
	 *
	 * @param authentication the authentication token containing the logged-in user's details
	 * @return a {@link ResponseEntity} containing a {@link HttpResponse} with
	 *         global statistics and authenticated user information
	 */
	@GetMapping("/stats")
	public ResponseEntity<HttpResponse> getGlobalStats(final Authentication authentication) {

	    log.info("Received request to retrieve global statistics");
	    UserDto userDto = UserUtils.getAuthenticatedUserDto(authentication);

	    log.debug("Authenticated user resolved: {}", userDto);

	    // Get stats
	    final StatsDto stats = customerService.getGlobalStats();
	    log.debug("Global stats retrieved: {}", stats);

	    // Build response
	    final HttpResponse response = HttpResponse.builder()
	            .timeStamp(LocalDateTime.now().toString())
	            .data(Map.of(
	                    "user", userDto,
	                    "stats", stats
	            ))
	            .message("Global statistics retrieved successfully")
	            .status(HttpStatus.OK)
	            .statusCode(HttpStatus.OK.value())
	            .build();

	    return ResponseEntity.ok(response);
	}

	/**
	 * Creates a new customer for the authenticated user.
	 *
	 * @param authentication the authentication token containing the logged user's details
	 * @param customer the customer data to create
	 * @return a ResponseEntity with the created customer and the user who performed the action
	 */
	@PostMapping("/create")
	public ResponseEntity<HttpResponse> createCustomer(
	        final Authentication authentication,
	        @RequestBody Customer customer
	) {
	    log.info("Request received to create a new customer");

	    // Retrieve authenticated user DTO
	    final UserDto userDto = userService.getUserDtoByEmail(
	            UserUtils.getAuthenticatedUserDto(authentication).getEmail()
	    );
	    log.debug("Authenticated user resolved: {}", userDto);

	    // Create customer
	    Customer createdCustomer = customerService.createCustomer(customer);
	    log.info("Customer created with ID: {}", createdCustomer.getId());

	    HttpResponse httpResponse = HttpResponse.builder()
	            .timeStamp(LocalDateTime.now().toString())
	            .data(Map.of(
	                "user", userDto,
	                "customer", createdCustomer
	            ))
	            .message("Customer created")
	            .status(HttpStatus.CREATED)
	            .statusCode(HttpStatus.CREATED.value())
	            .build();

	    // Build response
	    ResponseEntity<HttpResponse> response =
	            ResponseEntity.created(getCustomerUri(createdCustomer.getId())).body(httpResponse);

	    log.debug("Response created successfully for user ID: {}", userDto.getId());
	    return response;
	}
	
	/**
	 * Retrieves a customer by its ID.
	 *
	 * @param authentication the authentication token containing the logged user's details
	 * @param id the ID of the customer to retrieve
	 * @return a ResponseEntity containing the customer data and the user who made the request
	 */
	@GetMapping("/get/{id}")
	public ResponseEntity<HttpResponse> getCustomer(
	        final Authentication authentication,
	        @PathVariable Long id
	) {
	    log.info("Request received to get customer with ID: {}", id);

	    // Retrieve authenticated user
	    final UserDto userDto = userService.getUserDtoByEmail(
	            UserUtils.getAuthenticatedUserDto(authentication).getEmail()
	    );
	    log.debug("Authenticated user resolved: {}", userDto);

	    // Retrieve customer
	    Customer customer = customerService.getCustomer(id);
	    log.info("Customer found with ID: {}", customer.getId());
	    
	    Collection<Invoice> invoices = customer.getInvoices();

	    HttpResponse httpResponse = HttpResponse.builder()
	            .timeStamp(LocalDateTime.now().toString())
	            .data(Map.of(
	                    "user", userDto,
	                    "customer", customer,
	                    "invoices", invoices
	            ))
	            .message("Customer retrieved successfully")
	            .status(HttpStatus.OK)
	            .statusCode(HttpStatus.OK.value())
	            .build();

	    log.debug("Response prepared successfully for customer ID: {}", id);
	    return ResponseEntity.ok(httpResponse);
	}
	
	/**
	 * Searches customers by name with pagination.
	 *
	 * @param authentication the authentication token of the logged-in user
	 * @param name optional name to search for (case-insensitive)
	 * @param page page number (zero-based, default 0)
	 * @param size page size (default 10)
	 * @return a ResponseEntity containing the authenticated user and the paginated customers
	 */
	@GetMapping("/search")
	public ResponseEntity<HttpResponse> searchCustomers(
	        final Authentication authentication,
	        @RequestParam(required = false) String name,
	        @RequestParam(defaultValue = "0") int page,
	        @RequestParam(defaultValue = "10") int size
	) {
	    log.info("Received request to search customers with name: '{}', page: {}, size: {}", name, page, size);

	    final UserDto user = userService.getUserDtoByEmail(
	            UserUtils.getAuthenticatedUserDto(authentication).getEmail()
	    );
	    log.debug("Authenticated user resolved: {}", user);

	    // Perform customer search
	    final Page<Customer> customersPaged = customerService.searchCustomers(name, page, size);
	    log.info("Found {} customers matching search criteria", customersPaged.getTotalElements());

	    // Build response
	    final HttpResponse response = HttpResponse.builder()
	            .timeStamp(LocalDateTime.now().toString())
	            .data(Map.of(
	                    "user", user,
	                    "customers", customersPaged
	            ))
	            .message("Customers retrieved successfully")
	            .status(HttpStatus.OK)
	            .statusCode(HttpStatus.OK.value())
	            .build();

	    log.debug("Response prepared successfully for user ID: {}", user.getId());
	    return ResponseEntity.ok(response);
	}

	/**
	 * Updates an existing customer.
	 *
	 * @param authentication the authentication token of the logged-in user
	 * @param customer the customer object containing updated information
	 * @return a ResponseEntity containing the authenticated user and the updated customer
	 */
	@PutMapping("/update")
	public ResponseEntity<HttpResponse> updateCustomer(
	        final Authentication authentication,
	        @RequestBody final Customer customer
	) {
	    log.info("Received request to update customer with ID: {}", customer.getId());

	    // Retrieve authenticated user
	    final UserDto userDto = userService.getUserDtoByEmail(
	            UserUtils.getAuthenticatedUserDto(authentication).getEmail()
	    );
	    log.debug("Authenticated user resolved: {}", userDto);

	    // Update customer
	    final Customer updatedCustomer = customerService.updateCustomer(customer);
	    log.info("Customer updated successfully with ID: {}", updatedCustomer.getId());

	    // Build response
	    final HttpResponse response = HttpResponse.builder()
	            .timeStamp(LocalDateTime.now().toString())
	            .data(Map.of(
	                    "user", userDto,
	                    "customer", updatedCustomer
	            ))
	            .message("Customer updated successfully")
	            .status(HttpStatus.OK)
	            .statusCode(HttpStatus.OK.value())
	            .build();

	    log.debug("Response prepared successfully for customer ID: {}", updatedCustomer.getId());
	    return ResponseEntity.ok(response);
	}
	
	/**
	 * Creates a new invoice for the authenticated user.
	 *
	 * @param authentication the authentication token of the logged-in user
	 * @param invoice the invoice object to create
	 * @return a ResponseEntity containing the authenticated user and the created invoice
	 */
	@PostMapping("/invoice/create")
	public ResponseEntity<HttpResponse> createInvoice(
	        final Authentication authentication,
	        @RequestBody final Invoice invoice
	) {
	    log.info("Received request to create a new invoice");

	    // Retrieve authenticated user
	    final UserDto userDto = userService.getUserDtoByEmail(
	            UserUtils.getAuthenticatedUserDto(authentication).getEmail()
	    );
	    log.debug("Authenticated user resolved: {}", userDto);

	    // Create invoice
	    final Invoice createdInvoice = customerService.createInvoice(invoice);
	    log.info("Invoice created with number: {}", createdInvoice.getInvoiceNumber());

	    final URI location = getInvoiceUri(createdInvoice.getId());

	    // Build response
	    final HttpResponse response = HttpResponse.builder()
	            .timeStamp(LocalDateTime.now().toString())
	            .data(Map.of(
	                    "user", userDto,
	                    "invoice", createdInvoice
	            ))
	            .message("Invoice created successfully")
	            .status(HttpStatus.CREATED)
	            .statusCode(HttpStatus.CREATED.value())
	            .build();

	    log.debug("Response prepared successfully for invoice ID: {}", createdInvoice.getId());
	    return ResponseEntity.created(location).body(response);
	}
	
	/**
	 * Prepares data for creating a new invoice by retrieving all customers
	 * and the authenticated user's information.
	 *
	 * @param authentication the authentication token of the logged-in user
	 * @return a ResponseEntity containing the authenticated user and the list of customers
	 */
	@GetMapping("/invoice/new")
	public ResponseEntity<HttpResponse> newInvoice(
	        final Authentication authentication
	) {
	    log.info("Received request to prepare data for new invoice");

	    // Retrieve authenticated user
	    final UserDto userDto = userService.getUserDtoByEmail(
	            UserUtils.getAuthenticatedUserDto(authentication).getEmail()
	    );
	    log.debug("Authenticated user resolved: {}", userDto);

	    // Retrieve all customers
	    final Iterable<Customer> customers = customerService.getCustomers();
	    log.info("Retrieved {} customers for invoice creation", 
	             customers instanceof Collection ? ((Collection<?>) customers).size() : -1);

	    // Build response
	    final HttpResponse response = HttpResponse.builder()
	            .timeStamp(LocalDateTime.now().toString())
	            .data(
            		Map.of(
	                    "user", userDto,
	                    "customers", customers
    				)
	            )
	            .message("Customers retrieved successfully for invoice creation")
	            .status(HttpStatus.OK)
	            .statusCode(HttpStatus.OK.value())
	            .build();

	    log.debug("Response prepared successfully for user ID: {}", userDto.getId());
	    return ResponseEntity.ok(response);
	}


	/**
	 * Retrieves a paginated list of invoices for the authenticated user.
	 *
	 * @param authentication the authentication token of the logged-in user
	 * @param page the page number (zero-based, default 0)
	 * @param size the page size (default 10)
	 * @return a ResponseEntity containing the authenticated user and the paginated invoices
	 */
	@GetMapping("/invoice/list")
	public ResponseEntity<HttpResponse> getInvoices(
	        final Authentication authentication,
	        @RequestParam(defaultValue = "0") int page,
	        @RequestParam(defaultValue = "10") int size
	) {
	    log.info("Received request to retrieve invoices - page: {}, size: {}", page, size);

	    // Retrieve authenticated user
	    final UserDto userDto = userService.getUserDtoByEmail(
	            UserUtils.getAuthenticatedUserDto(authentication).getEmail()
	    );
	    log.debug("Authenticated user resolved: {}", userDto);

	    // Fetch invoices with pagination
	    final Page<Invoice> invoicesPaged = customerService.getInvoices(page, size);
	    log.info("Retrieved {} invoices for page {}", invoicesPaged.getNumberOfElements(), page);

	    // Build response
	    final HttpResponse response = HttpResponse.builder()
	            .timeStamp(LocalDateTime.now().toString())
	            .data(Map.of(
	                    "user", userDto,
	                    "page", invoicesPaged
	            ))
	            .message("Invoices retrieved successfully")
	            .status(HttpStatus.OK)
	            .statusCode(HttpStatus.OK.value())
	            .build();

	    log.debug("Response prepared successfully for user ID: {}", userDto.getId());
	    return ResponseEntity.ok(response);
	}
	
	/**
	 * Retrieves a specific invoice by its ID for the authenticated user.
	 *
	 * @param authentication the authentication token containing the logged-in user
	 * @param id the ID of the invoice to retrieve
	 * @return a {@link ResponseEntity} containing the invoice and user info
	 */
	@GetMapping("/invoice/get/{id}")
	public ResponseEntity<HttpResponse> getInvoice(
	        final Authentication authentication,
	        @PathVariable final Long id
	) {
	    log.info("Received request to fetch invoice with ID: {}", id);

	    // Retrieve authenticated user
	    final UserDto userDto = userService.getUserDtoByEmail(
	            UserUtils.getAuthenticatedUserDto(authentication).getEmail()
	    );
	    log.debug("Authenticated user resolved: {}", userDto);

	    // Retrieve invoice
	    log.debug("Fetching invoice with ID: {}", id);
	    final Invoice invoice = customerService.getInvoice(id);
	    log.info("Invoice {} successfully retrieved", id);

	    // Build response
	    HttpResponse response = HttpResponse.builder()
	            .timeStamp(LocalDateTime.now().toString())
	            .data(
	                    Map.of(
	                            "user", userDto,
	                            "invoice", invoice
	                    )
	            )
	            .message("Invoice retrieved")
	            .status(HttpStatus.OK)
	            .statusCode(HttpStatus.OK.value())
	            .build();

	    log.debug("Response prepared for invoice {}: {}", id, response);

	    return ResponseEntity.ok(response);
	}
	
	/**
	 * Adds a new invoice to a customer identified by its ID.
	 *
	 * @param authentication the authentication token containing the logged-in user
	 * @param id        the ID of the customer to which the invoice will be added
	 * @param invoice   the invoice object to associate with the customer
	 * @return a {@link ResponseEntity} containing the operation result
	 */
	@PostMapping("/invoice/addtocustomer/{id}")
	public ResponseEntity<HttpResponse> addInvoiceToCustomer(
	        Authentication authentication,
	        @PathVariable("id") final Long id,
	        @RequestBody final Invoice invoice
	) {
	    log.info("Received request to add invoice to customer with ID: {}", id);
	    log.debug("Invoice payload received: {}", invoice);

	    // Retrieve authenticated user
	    // Retrieve authenticated user
	    final UserDto userDto = userService.getUserDtoByEmail(
	            UserUtils.getAuthenticatedUserDto(authentication).getEmail()
	    );
	    log.debug("Authenticated user resolved: {}", userDto);

	    // Add invoice to customer
	    log.debug("Adding invoice to customer with ID: {}", id);
	    customerService.addInvoiceToCustomer(id, invoice);
	    log.info("Invoice successfully added to customer {}", id);

	    // Prepare response
	    final HttpResponse response = HttpResponse.builder()
	            .timeStamp(LocalDateTime.now().toString())
	            .data(
	                    Map.of(
	                            "user", userDto,
	                            "customers", customerService.getCustomers()
	                    )
	            )
	            .message(String.format("Invoice added to customer with ID: %s", id))
	            .status(HttpStatus.OK)
	            .statusCode(HttpStatus.OK.value())
	            .build();

	    log.debug("Response prepared for invoice addition to customer {}: {}", id, response);

	    return ResponseEntity.ok(response);
	}

	/**
	 * Builds a generic URI template for user-related operations.
	 * <p>
	 * This URI is used as a placeholder in {@link #saveUser(User)} responses.
	 *
	 * @return A {@link URI} pointing to the user resource endpoint.
	 */
    private URI getCustomerUri(Long customerId) {
        return URI.create(
            fromCurrentContextPath()
                .path("/customer/get/" + customerId)
                .toUriString()
        );
    }
    
    /**
     * Builds the URI for accessing a specific invoice by its ID.
     *
     * <p>This URI can be used in the Location header of a ResponseEntity
     * when returning a newly created invoice.</p>
     *
     * @param invoiceId the ID of the invoice
     * @return a URI pointing to the endpoint for retrieving the invoice
     */
    private URI getInvoiceUri(Long invoiceId) {
        return URI.create(
            fromCurrentContextPath()
                .path("/customer/invoice/get/" + invoiceId)
                .toUriString()
        );
    }

}
