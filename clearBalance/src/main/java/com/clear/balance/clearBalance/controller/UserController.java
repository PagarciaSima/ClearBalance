package com.clear.balance.clearBalance.controller;

import static org.springframework.security.authentication.UsernamePasswordAuthenticationToken.unauthenticated;
import static org.springframework.web.servlet.support.ServletUriComponentsBuilder.fromCurrentContextPath;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.clear.balance.clearBalance.Utils.ExceptionUtils;
import com.clear.balance.clearBalance.domain.HttpResponse;
import com.clear.balance.clearBalance.domain.User;
import com.clear.balance.clearBalance.domain.UserPrincipal;
import com.clear.balance.clearBalance.dto.LoginRequestDto;
import com.clear.balance.clearBalance.dto.UserDto;
import com.clear.balance.clearBalance.dtoMapper.UserDtoMapper;
import com.clear.balance.clearBalance.exeception.ApiException;
import com.clear.balance.clearBalance.provider.TokenProvider;
import com.clear.balance.clearBalance.service.RoleService;
import com.clear.balance.clearBalance.service.UserService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * REST controller for managing user-related operations such as registration.
 * <p>
 * Provides endpoints for creating and managing user accounts. Uses
 * {@link UserService} to handle business logic.
 */
@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
@Slf4j
public class UserController {

	private static final String TOKEN_PREFIX = "Bearer ";
	private final UserService userService;
	private final AuthenticationManager authenticationManager;
	private final TokenProvider tokenProvider;
	private final RoleService roleService;
	private final HttpServletRequest request;
	private final HttpServletResponse response;

    /**
     * Handles user login requests.
     * <p>
     * This method authenticates the user using their email and password,
     * retrieves the authenticated {@link UserDto}, and then:
     * <ul>
     *     <li>If the user is using MFA (multi-factor authentication), it sends a verification code.</li>
     *     <li>If not, it sends the standard login response.</li>
     * </ul>
     *
     * @param loginRequestDto the login request containing email and password
     * @return a {@link ResponseEntity} containing either the MFA verification response
     *         or the standard user login response
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody @Valid LoginRequestDto loginRequestDto) {
        log.info("Login attempt for user: {}", loginRequestDto.getEmail());

        Authentication authentication = authenticate(loginRequestDto.getEmail(), loginRequestDto.getPassword());
        log.debug("Authentication object created for user: {}", loginRequestDto.getEmail());

        UserDto userDto = getAuthenticatedUserDto(authentication);
        if (userDto == null) {
            log.warn("Authenticated UserDto is null for user: {}", loginRequestDto.getEmail());
            return ResponseEntity.status(500).body("Failed to retrieve authenticated user information.");
        }

        log.info("User '{}' authenticated successfully. MFA enabled: {}", userDto.getEmail(), userDto.isUsingMfa());

        return userDto.isUsingMfa() ? sendVerificationCode(userDto) : sendResponse(userDto);
    }
    
	/**
	 * Registers a new user in the system.
	 * <p>
	 * This endpoint accepts a {@link User} object, delegates the creation process
	 * to {@link UserService#create(User)}, and returns an HTTP response containing
	 * the created user information.
	 *
	 * @param user The {@link User} entity to be registered.
	 * @return A {@link ResponseEntity} containing a {@link HttpResponse} with user
	 *         details.
	 * @throws InterruptedException if the thread is interrupted during execution
	 *                              (for simulation or delay purposes).
	 */
	@PostMapping("/register")
	public ResponseEntity<HttpResponse> saveUser(@RequestBody @Valid User user) throws InterruptedException {
		log.info("Received user registration request for email: {}", user.getEmail());

		try {
			// Call service layer to handle user creation
			UserDto userDto = userService.create(user);
			log.debug("User created successfully in service layer: {}", user.getEmail());

			// Build and return response
			ResponseEntity<HttpResponse> response = ResponseEntity.created(getUri())
					.body(
							HttpResponse.builder()
							.timeStamp(LocalDateTime.now().toString())
							.data(Map.of("user", userDto))
							.message(String.format("User account created for user %s", user.getFirstName()))
							.status(HttpStatus.CREATED).statusCode(HttpStatus.CREATED.value())
							.build());

			log.info("Registration completed successfully for email: {}", user.getEmail());
			return response;

		} catch (Exception e) {
			log.error("Error while registering user '{}': {}", user.getEmail(), e.getMessage(), e);
			throw e; // Let global exception handler process it
		}
	}

    /**
     * Retrieves the profile information of the authenticated user.
     *
     * @param authentication The authentication object containing the user's details.
     * @return ResponseEntity containing HttpResponse with user profile data and HTTP status.
     */
    @GetMapping("/profile")
    public ResponseEntity<HttpResponse> profile(Authentication authentication) {
        log.info("Profile request received for user: {}", authentication.getName());

        UserDto user = userService.getUserDtoByEmail(authentication.getName());
        log.debug("User retrieved from service: {}", user);

        HttpResponse response = HttpResponse.builder()
                .timeStamp(LocalDateTime.now().toString())
                .data(Map.of("user", user))
                .message("Profile retrieved successfully")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build();

        log.info("Profile response prepared for user: {}", authentication.getName());
        return ResponseEntity.ok().body(response);
    }
    
    /**
     * Handles password reset requests for a given user email.
     * <p>
     * This endpoint triggers the password reset process by delegating to the
     * {@link UserService#resetPassword(String)} method. If the email exists,
     * a reset link or temporary password is sent to the user.
     * </p>
     *
     * @param email the email address of the user requesting the password reset
     * @return a {@link ResponseEntity} containing an {@link HttpResponse} with the result
     */
    @GetMapping("/resetpassword/{email}")
    public ResponseEntity<HttpResponse> resetPassword(@PathVariable("email") String email) {
        log.info("Received password reset request for email: {}", email);

        UserDto user = userService.resetPassword(email);
        log.info("Password reset process completed for user: {}", user.getId());

        HttpResponse response = HttpResponse.builder()
                .timeStamp(LocalDateTime.now().toString())
                .message("Email sent. Please check your email to reset your password")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build();

        log.debug("Password reset response generated for email: {}", email);

        return ResponseEntity.ok().body(response);
    }
    
    /**
     * Verifies a password reset request using the provided verification key.
     * <p>
     * This endpoint is called when the user clicks the password reset link sent to their email.
     * It performs the following actions:
     * <ul>
     *   <li>Logs the received verification key.</li>
     *   <li>Delegates the verification process to {@code userService.verifyPassword(key)}.</li>
     *   <li>Builds an {@link HttpResponse} instructing the client to prompt the user
     *       to enter a new password.</li>
     * </ul>
     * </p>
     *
     * @param key the unique verification key included in the password reset URL
     * @return a {@link ResponseEntity} containing an {@link HttpResponse} with the user data
     *         and a message indicating that the user may proceed to set a new password
     */
    @GetMapping("/verify/password/{key}")
    public ResponseEntity<HttpResponse> verifyPassword(@PathVariable("key") String key) {
        log.info("Verifying password reset key: {}", key);
        UserDto user = userService.verifyPassword(key);
        log.debug("Password verification process completed");

        HttpResponse response = HttpResponse.builder()
                .timeStamp(LocalDateTime.now().toString())
                .data(Map.of("user", user))
                .message("Please enter a new password")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build();


        return ResponseEntity.ok().body(response);
    }
    
    @PatchMapping("/resetpassword/{key}/{password}/{confirmPassword}")
    public ResponseEntity<HttpResponse> resetPassword(
    		@PathVariable("key") String key,
    		@PathVariable("password") String password,
    		@PathVariable("confirmPassword") String confirmPassword
	) {
        log.info("Resetting password using key: {}", key);
        UserDto user = userService.renewPassword(key, password, confirmPassword);
        log.debug("Password reset process completed");

        HttpResponse response = HttpResponse.builder()
                .timeStamp(LocalDateTime.now().toString())
                .data(Map.of("user", user))
                .message("Password successfully changed")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build();

        return ResponseEntity.ok().body(response);
    }
    
	/**
	 * Verifies a user's two-factor authentication code and returns authentication tokens if valid.
	 * <p>
	 * This endpoint validates the provided verification code for the given email address. 
	 * If the verification is successful, it returns a response containing the authenticated user's data, 
	 * an access token, and a refresh token. Otherwise, an appropriate error is thrown and handled globally.
	 * </p>
	 *
	 * @param email the user's email address
	 * @param code the verification code to validate
	 * @return a {@link ResponseEntity} containing an {@link HttpResponse} with user details and tokens
	 */
	@GetMapping("/verify/code/{email}/{code}")
	public ResponseEntity<HttpResponse> verifyCode(@PathVariable String email, @PathVariable String code) {
	    log.info("Received request to verify code '{}' for user '{}'", code, email);

	    try {
	        UserDto user = userService.verifyCode(email, code);
	        log.info("Verification successful for user '{}'", email);

	        Map<String, Object> data = new LinkedHashMap<>();
	        data.put("user", user);
	        data.put("access_token", tokenProvider.createAccessToken(getUserPrincipal(user)));
	        data.put("refresh_token", tokenProvider.createRefreshToken(getUserPrincipal(user)));

	        HttpResponse response = HttpResponse.builder()
	                .timeStamp(LocalDateTime.now().toString())
	                .data(data)
	                .message("Login successful")
	                .status(HttpStatus.OK)
	                .statusCode(HttpStatus.OK.value())
	                .build();

	        return ResponseEntity.ok().body(response);
	    } catch (Exception e) {
	        log.error("Failed to verify code '{}' for user '{}': {}", code, email, e.getMessage());
	        throw e; // rethrow to be handled by global exception handler
	    }
	}
	
	/**
	 * Verifies a user account using the provided verification key.
	 * <p>
	 * This endpoint is invoked when the user clicks the account verification link
	 * sent to their email during the registration process. It performs the following actions:
	 * <ul>
	 *   <li>Logs the received verification key.</li>
	 *   <li>Delegates the verification logic to {@code userService.verifyAccount(key)}.</li>
	 *   <li>Logs completion of the verification for debugging purposes.</li>
	 *   <li>Builds an {@link HttpResponse} indicating that the account has been successfully verified.</li>
	 * </ul>
	 * </p>
	 *
	 * @param key the unique verification key included in the account activation URL
	 * @return a {@link ResponseEntity} containing an {@link HttpResponse} with a success message
	 */
	@GetMapping("/verify/account/{key}")
	public ResponseEntity<HttpResponse> verifyAccount(@PathVariable String key) {
		log.info("Verifying account with key: {}", key);
        UserDto user = userService.verifyAccount(key);
        log.debug("Account verification process completed for user ID: {}", user.getId());
        HttpResponse response = HttpResponse.builder()
                .timeStamp(LocalDateTime.now().toString())
                .message("Account verified successfully")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build();

        return ResponseEntity.ok().body(response);
	}
	
	@GetMapping("/refresh/token")
	public ResponseEntity<HttpResponse> refreshToken(HttpServletRequest request) {
		log.info("Received token refresh request");
		HttpResponse response = null;
		String token = request.getHeader(HttpHeaders.AUTHORIZATION).substring(TOKEN_PREFIX.length());

		if(isHeaderTokenValid(request, token)) {
			UserDto user = this.userService.getUserDtoByEmail(this.tokenProvider.getSubject(token, request));
			response = HttpResponse.builder()
	                .timeStamp(LocalDateTime.now().toString())
	                .data(
	                		Map.of(
	                				"user", user,
	                				"refresh_token", tokenProvider.createRefreshToken(getUserPrincipal(user))
            				)
            		)
	                .message("Token refreshed successfully")
	                .status(HttpStatus.OK)
	                .statusCode(HttpStatus.OK.value())
	                .build();
		} else {
			response = HttpResponse.builder()
	                .timeStamp(LocalDateTime.now().toString())
	                .reason("Refresh token missing or invalid")
	                .developerMessage("Refresh token missing or invalid")
	                .status(HttpStatus.BAD_REQUEST)
	                .statusCode(HttpStatus.BAD_REQUEST.value())
	                .build();
		}
		
        return ResponseEntity.ok().body(response);
	}

	/**
	 * Validates whether the authorization header contains a valid token.
	 * <p>
	 * This method checks the following conditions:
	 * <ul>
	 *   <li>The {@code Authorization} header exists in the request.</li>
	 *   <li>The header starts with the expected token prefix (e.g., "Bearer ").</li>
	 *   <li>The provided token is valid according to the {@code tokenProvider}, using the token's subject.</li>
	 * </ul>
	 * </p>
	 *
	 * @param request the incoming HTTP request containing the authorization header
	 * @param token the JWT or security token extracted from the authorization header
	 * @return {@code true} if the header and token are valid; {@code false} otherwise
	 */
	private boolean isHeaderTokenValid(HttpServletRequest request, String token) {
	    String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
	    return authHeader != null && 
	           authHeader.startsWith(TOKEN_PREFIX) &&
	           tokenProvider.isTokenValid(tokenProvider.getSubject(token, request), token);
	}
	
	/**
     * Handles unmapped or invalid HTTP requests and returns a detailed error response.
     *
     * @param request The HttpServletRequest object containing request details.
     * @return ResponseEntity containing HttpResponse with error details and HTTP 400 status.
     */
    @RequestMapping("/error")
    public ResponseEntity<HttpResponse> handleError(HttpServletRequest request) {
        String method = request.getMethod();
        String path = request.getRequestURI();
        log.warn("Unhandled request received: {} {}", method, path);

        HttpResponse response = HttpResponse.builder()
                .timeStamp(LocalDateTime.now().toString())
                .reason("There is no mapping for a " + method + " request for this path on the server")
                .status(HttpStatus.BAD_REQUEST)
                .statusCode(HttpStatus.BAD_REQUEST.value())
                .build();

        log.info("Returning BAD_REQUEST response for {} {}", method, path);
        return ResponseEntity.badRequest().body(response);
    }

	/**
	 * Builds a generic URI template for user-related operations.
	 * <p>
	 * This URI is used as a placeholder in {@link #saveUser(User)} responses.
	 *
	 * @return A {@link URI} pointing to the user resource endpoint.
	 */
	private URI getUri() {
		return URI.create(fromCurrentContextPath().path("/user/get/<userId>").toUriString());
	}

	private ResponseEntity<HttpResponse> sendVerificationCode(UserDto user) {
		this.userService.sendVerificationCode(user);
		return ResponseEntity.ok()
				.body(HttpResponse.builder().timeStamp(LocalDateTime.now().toString()).data(Map.of("user", user))
						.message("Verification code sent via SMS").status(HttpStatus.OK)
						.statusCode(HttpStatus.OK.value()).build());
	}

	/**
	 * Builds and returns a successful login {@link ResponseEntity} containing the
	 * {@link HttpResponse}.
	 * <p>
	 * This method generates JWT access and refresh tokens for the given user and
	 * returns them along with the user data in the response body. Logs are included
	 * to trace token generation and response building.
	 * </p>
	 *
	 * @param user the {@link UserDto} representing the authenticated user
	 * @return a {@link ResponseEntity} with {@link HttpResponse} containing user
	 *         info and tokens
	 * @throws ApiException if the user is null or token generation fails
	 */
	private ResponseEntity<HttpResponse> sendResponse(UserDto user) {
	    Map<String, Object> data = new LinkedHashMap<>();
	    data.put("user", user);
	    data.put("access_token", tokenProvider.createAccessToken(getUserPrincipal(user)));
	    data.put("refresh_token", tokenProvider.createRefreshToken(getUserPrincipal(user)));

	    return ResponseEntity.ok().body(
	            HttpResponse.builder()
	                    .timeStamp(LocalDateTime.now().toString())
	                    .data(data)
	                    .message("Login successful")
	                    .status(HttpStatus.OK)
	                    .statusCode(HttpStatus.OK.value())
	                    .build()
	    );
	}

	/**
	 * Retrieves a {@link UserPrincipal} based on the provided {@link UserDto}.
	 * <p>
	 * This method fetches the full user details using the email and retrieves the
	 * associated permissions through the role service. It then builds and returns a
	 * {@link UserPrincipal} object.
	 * </p>
	 *
	 * @param user the {@link UserDto} containing basic user information
	 * @return a {@link UserPrincipal} with full user and permission details
	 */
	private UserPrincipal getUserPrincipal(UserDto user) {

		log.debug("Retrieving UserPrincipal for user with email: {}", user.getEmail());

		try {
			var userDto = userService.getUserDtoByEmail(user.getEmail());
			log.trace("Fetched UserDto for email {}: {}", user.getEmail(), userDto);

			var role = roleService.getRoleByUserId(user.getId());
			log.trace("Fetched role for user ID {}: {}", user.getId(), role);

			var userPrincipal = new UserPrincipal(UserDtoMapper.toUser(userDto), role);

			log.info("Successfully created UserPrincipal for user: {}", user.getEmail());
			return userPrincipal;
		} catch (Exception e) {
			log.error("Error while creating UserPrincipal for user {}: {}", user.getEmail(), e.getMessage(), e);
			throw e;
		}
	}
	
    /**
     * Attempts to authenticate a user with the given email and password.
     * <p>
     * If authentication succeeds, returns an {@link Authentication} object.
     * If authentication fails, logs the error, writes a detailed JSON error response
     * to the client using {@link ExceptionUtils#processError}, and throws an {@link ApiException}.
     *
     * @param email    The email of the user attempting to authenticate.
     * @param password The password provided by the user.
     * @return An {@link Authentication} object if authentication succeeds.
     * @throws ApiException if authentication fails.
     */
    private Authentication authenticate(String email, String password) {
        log.debug("Starting authentication process for user: {}", email);
        Authentication authentication = null;

        try {
            authentication = authenticationManager.authenticate(
                    unauthenticated(email, password));
            log.info("User '{}' successfully authenticated", email);
        } catch (Exception e) {
            log.error("Authentication failed for user '{}': {}", email, e.getMessage(), e);
            ExceptionUtils.processError(request, response, e);
            log.debug("ApiException thrown for user '{}'", email);
            throw new ApiException(e.getMessage());
        }

        return authentication;
    }
    
    /**
     * Retrieves the authenticated user's {@link UserDto} from the given {@link Authentication} object.
     * <p>
     * If the {@link Authentication} principal is not an instance of {@link UserPrincipal} or is null,
     * this method returns {@code null}.
     *
     * @param authentication the {@link Authentication} object containing the authenticated principal
     * @return the {@link UserDto} of the authenticated user, or {@code null} if not available
     */
    private UserDto getAuthenticatedUserDto(Authentication authentication) {
        if (authentication == null || authentication.getPrincipal() == null) {
            log.warn("Authentication or principal is null. Cannot retrieve UserDto.");
            return null;
        }

        Object principal = authentication.getPrincipal();

        if (principal instanceof UserPrincipal) {
            UserDto userDto = ((UserPrincipal) principal).getUser();
            log.debug("Retrieved UserDto for authenticated user: {}", userDto.getEmail());
            return userDto;
        } else {
            log.warn("Authentication principal is not an instance of UserPrincipal. Found: {}", principal.getClass().getName());
            return null;
        }
    }
}
