package com.clear.balance.clearBalance.controller;

import static org.springframework.security.authentication.UsernamePasswordAuthenticationToken.unauthenticated;
import static org.springframework.web.servlet.support.ServletUriComponentsBuilder.fromCurrentContextPath;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.clear.balance.clearBalance.Utils.ExceptionUtils;
import com.clear.balance.clearBalance.Utils.UserUtils;
import com.clear.balance.clearBalance.domain.response.HttpResponse;
import com.clear.balance.clearBalance.domain.user.User;
import com.clear.balance.clearBalance.domain.user.UserPrincipal;
import com.clear.balance.clearBalance.dto.login.LoginRequestDto;
import com.clear.balance.clearBalance.dto.profile.SettingsFormDto;
import com.clear.balance.clearBalance.dto.profile.UpdatePasswordFormDto;
import com.clear.balance.clearBalance.dto.profile.UpdateProfileFormDto;
import com.clear.balance.clearBalance.dto.profile.events.UserEventResponseDto;
import com.clear.balance.clearBalance.dto.role.RoleDto;
import com.clear.balance.clearBalance.dto.user.UserDto;
import com.clear.balance.clearBalance.dtoMapper.UserDtoMapper;
import com.clear.balance.clearBalance.enumeration.EventType;
import com.clear.balance.clearBalance.event.NewUserEvent;
import com.clear.balance.clearBalance.exeception.ApiException;
import com.clear.balance.clearBalance.provider.TokenProvider;
import com.clear.balance.clearBalance.service.EventService;
import com.clear.balance.clearBalance.service.UserRoleService;
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
	private final EventService eventService;
	private final UserRoleService userRoleService;

	private final AuthenticationManager authenticationManager;
	private final TokenProvider tokenProvider;
	private final HttpServletRequest request;
	private final HttpServletResponse response;
	private final ApplicationEventPublisher eventPublisher;

	/**
	 * Handles user login requests by authenticating the provided credentials and returning
	 * either an MFA verification response or a standard authentication response.
	 *
	 * <p>Flow:
	 * <ul>
	 *   <li>Authenticates the user via {@code authenticate()}.</li>
	 *   <li>Returns an MFA verification step if MFA is enabled.</li>
	 *   <li>Otherwise returns the authenticated user response.</li>
	 * </ul>
	 *
	 * @param loginRequestDto the login request containing email and password
	 * @return an MFA verification response or a normal login response
	 */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody @Valid LoginRequestDto loginRequestDto) {
        log.info("Login attempt for user: {}", loginRequestDto.getEmail());
        UserDto userDto = this.authenticate(loginRequestDto.getEmail(), loginRequestDto.getPassword());
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

        UserDto user = userService.getUserDtoByEmail(UserUtils.getAuthenticatedUserDto(authentication).getEmail());
        log.debug("User retrieved from service: {}", user);
        List<RoleDto> rolesDtoList = userRoleService.getAllRoles();

        HttpResponse response = HttpResponse.builder()
                .timeStamp(LocalDateTime.now().toString())
                .data(
                	Map.of(
                		"user", user,
                		"roles", rolesDtoList
                	)
                )
                .message("Profile retrieved successfully")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build();

        log.info("Profile response prepared for user: {}", authentication.getName());
        return ResponseEntity.ok().body(response);
    }
    
    /**
     * Updates the details of an existing user.
     *
     * <p>This endpoint receives a {@link UpdateProfileFormDto} containing the user fields
     * to be updated. Validation is applied to ensure all required fields meet the
     * specified constraints. If the update is successful, a {@link HttpResponse}
     * object containing the updated user data is returned.</p>
     *
     * <p>In case of any exception during the update process, the error is logged and
     * rethrown for centralized exception handling.</p>
     *
     * @param user the DTO containing the updated user information; must be valid and not null
     * @return a {@link ResponseEntity} containing a {@link HttpResponse} with the updated user
     * @throws RuntimeException if an unexpected error occurs during the update process
     *
     * @see UpdateProfileFormDto
     * @see UserDto
     * @see UserService#updateUserDetails(UpdateProfileFormDto)
     */
    @PatchMapping("/update")
    public ResponseEntity<HttpResponse> updateUser(
            @RequestBody @Valid UpdateProfileFormDto user
    ) {
        log.info("Received request to update user with ID: {}", user.getId());
        try {
            UserDto updatedUser = userService.updateUserDetails(user);
        	this.eventPublisher.publishEvent(new NewUserEvent(updatedUser.getEmail(), EventType.PROFILE_UPDATE));

            log.debug("User updated successfully: {}", updatedUser);

            HttpResponse response = HttpResponse.builder()
                    .timeStamp(LocalDateTime.now().toString())
                    .data(
                    		Map.of(
                    				"user", updatedUser,
                    				"roles", userRoleService.getAllRoles()
                    		)
                    		
                    )
                    .message("User updated successfully")
                    .status(HttpStatus.OK)
                    .statusCode(HttpStatus.OK.value())
                    .build();

            return ResponseEntity.ok().body(response);

        } catch (Exception e) {
        	log.error("Error updating user with ID {}: {}", user.getId(), e.getMessage(), e);
            throw e; 
        }
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
    
    /**
     * Resets the user's password using a password-reset key typically sent by email.
     * <p>
     * This endpoint validates the provided key and ensures the new password and its
     * confirmation match. If the key is valid and the validation succeeds, the user's
     * password is updated accordingly.
     *
     * @param key              Unique reset key associated with the user requesting the password reset.
     * @param password         The new password to be assigned to the user.
     * @param confirmPassword  Confirmation of the new password; must match {@code password}.
     * @return A {@link ResponseEntity} containing an {@link HttpResponse} with the updated user information
     *         and the status of the operation.
     */
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
	    	this.eventPublisher.publishEvent(new NewUserEvent(user.getEmail(), EventType.LOGIN_ATTEMPT_SUCCESS));

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
	
	/**
	 * Updates the password of the currently authenticated user.
	 * <p>
	 * This endpoint requires a valid authentication context and a request body
	 * containing the current password and the new password fields. The service
	 * verifies the current password, validates the new one, and persists the change
	 * if the operation is valid.
	 *
	 * @param authentication             Authentication object containing the authenticated user's details.
	 * @param updatePasswordFormDto      DTO containing the current password, new password, and confirmation.
	 * @return A {@link ResponseEntity} containing an {@link HttpResponse} indicating the result
	 *         of the password update operation.
	 */
	@PatchMapping("/update/password")
	public ResponseEntity<HttpResponse> updatePassoword(
			Authentication authentication,
			@RequestBody @Valid UpdatePasswordFormDto updatePasswordFormDto
	) {
        UserDto userDto = UserUtils.getAuthenticatedUserDto(authentication);

        log.debug("Updating password for user ID: {}", userDto.getId());
        this.userService.updatePassword(userDto.getId(), updatePasswordFormDto);
    	this.eventPublisher.publishEvent(new NewUserEvent(userDto.getEmail(), EventType.PASSWORD_UPDATE));

        HttpResponse response = HttpResponse.builder()
        		.data(
    	                Map.of(
    	                    "user", userDto,
    	                    "roles", userRoleService.getAllRoles()

    	                )
	            )
                .timeStamp(LocalDateTime.now().toString())
                .message("Password updated successfully")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build();

        return ResponseEntity.ok().body(response);
	}
	
	/**
	 * Updates the role of the currently authenticated user.
	 * <p>
	 * This endpoint receives the new role name in the request body and updates
	 * the user's role accordingly. It performs the following steps:
	 * </p>
	 * <ul>
	 *     <li>Retrieves the authenticated user information from the security context.</li>
	 *     <li>Delegates the role update operation to {@link UserRoleService#updateUserRole(Long, String)}.</li>
	 *     <li>Fetches the updated user and maps it to a {@link UserDto}.</li>
	 *     <li>Includes the updated user data and the list of all available roles in the response payload.</li>
	 * </ul>
	 * <p>
	 * If the provided role does not exist or the update operation fails,
	 * an appropriate exception is thrown and handled globally.
	 * </p>
	 *
	 * @param authentication the authentication object containing the currently logged-in user
	 * @param roleName       the name of the new role to assign to the authenticated user
	 * @return a {@link ResponseEntity} containing an {@link HttpResponse} with the updated user information,
	 *         the list of all roles, and a success message
	 */
	@PatchMapping("/update/role/{roleName}")
	public ResponseEntity<HttpResponse> updateRole(
	        Authentication authentication,
	        @PathVariable String roleName
	) {
	    UserDto userDto = UserUtils.getAuthenticatedUserDto(authentication);
	    log.debug("Updating role to {} for user ID: {}", roleName, userDto.getId());

	    this.userRoleService.updateUserRole(userDto.getId(), roleName);
    	this.eventPublisher.publishEvent(new NewUserEvent(userDto.getEmail(), EventType.ROLE_UPDATE));

	    User updatedUser = this.userService.getUserWithRoleById(userDto.getId());
	    UserDto updatedUserDto = UserDtoMapper.fromUser(updatedUser);

	    HttpResponse response = HttpResponse.builder()
	            .data(
	                Map.of(
	                    "user", updatedUserDto,
	                    "roles", userRoleService.getAllRoles()

	                )
	            )
	            .timeStamp(LocalDateTime.now().toString())
	            .message("User role updated successfully")
	            .status(HttpStatus.OK)
	            .statusCode(HttpStatus.OK.value())
	            .build();

	    return ResponseEntity.ok(response);
	}
	
	/**
	 * Updates the account settings of the currently authenticated user.
	 * <p>
	 * This endpoint allows the user to change their 'enabled' and 'notLocked' status.
	 * After updating, it returns the updated user information along with all available roles.
	 * </p>
	 *
	 * @param authentication the authentication object containing the currently logged-in user
	 * @param form           a {@link SettingsFormDto} containing the new account settings
	 * @return a {@link ResponseEntity} containing a {@link HttpResponse} with the updated user and roles
	 */
	@PatchMapping("/update/settings")
	public ResponseEntity<HttpResponse> updateAccountSettings(
	        Authentication authentication, 
	        @RequestBody @Valid SettingsFormDto form) {

	    UserDto userDto = UserUtils.getAuthenticatedUserDto(authentication);
	    log.info("Updating account settings for user ID: {}", userDto.getId());

	    userService.updateAccountSettings(userDto.getId(), form.getEnabled(), form.getNotLocked());
    	this.eventPublisher.publishEvent(new NewUserEvent(userDto.getEmail(), EventType.ACCOUNT_SETTINGS_UPDATE));

	    User updatedUser = this.userService.getUserWithRoleById(userDto.getId());
	    UserDto updatedUserDto = UserDtoMapper.fromUser(updatedUser);

	    HttpResponse response = HttpResponse.builder()
	            .data(Map.of(
	                    "user", updatedUserDto,
	                    "roles", userRoleService.getAllRoles()

	            ))
	            .timeStamp(LocalDateTime.now().toString())
	            .message("User account settings updated successfully")
	            .status(HttpStatus.OK)
	            .statusCode(HttpStatus.OK.value())
	            .build();

	    log.info("Account settings updated successfully for user ID: {}", userDto.getId());
	    return ResponseEntity.ok(response);
	}
	
	/**
	 * Toggles the Multi-Factor Authentication (MFA) setting for the currently authenticated user.
	 * <p>
	 * This endpoint retrieves the authenticated user's information, delegates the MFA toggle operation
	 * to the {@code userService}, and returns a structured HTTP response containing the updated user data
	 * and the list of available roles.
	 * </p>
	 *
	 * <p>
	 * A success message is included, indicating the new MFA state after the toggle operation.
	 * </p>
	 *
	 * @param authentication the authentication object containing the details of the currently logged-in user
	 * @return a {@link ResponseEntity} containing a {@link HttpResponse} with updated user information and roles
	 * @throws InterruptedException if the execution is interrupted during processing
	 */
	@PatchMapping("/togglemfa")
    public ResponseEntity<HttpResponse> toggleMfa(Authentication authentication) throws InterruptedException {
	    UserDto userDto = UserUtils.getAuthenticatedUserDto(authentication);
        log.info("Toggling MFA for user ID: {}", userDto.getId());
        UserDto updatedUserDto = userService.toggleMfa(userDto.getEmail());
    	this.eventPublisher.publishEvent(new NewUserEvent(userDto.getEmail(), EventType.MFA_UPDATE));

        HttpResponse response = HttpResponse.builder()
	            .data(Map.of(
	                    "user", updatedUserDto,
	                    "roles", userRoleService.getAllRoles()
	                    
	            ))
	            .timeStamp(LocalDateTime.now().toString())
	            .message("User MFA setting toggled successfully, current state: " + updatedUserDto.isUsingMfa())
	            .status(HttpStatus.OK)
	            .statusCode(HttpStatus.OK.value())
	            .build();
        log.info("MFA toggled successfully for user ID: {}", userDto.getId());
        return ResponseEntity.ok(response);
    }
	
	/**
	 * Updates the profile image of the currently authenticated user.
	 * <p>
	 * This endpoint allows the authenticated user to upload a new profile image.
	 * The uploaded image is processed and saved via the {@link UserService#updateImage(UserDto, MultipartFile)} method.
	 * The response includes the updated user information along with all available roles.
	 * </p>
	 *
	 * @param authentication the authentication object containing the currently logged-in user's details
	 * @param image the uploaded image file to be set as the user's new profile picture
	 * @return a {@link ResponseEntity} containing an {@link HttpResponse} with the updated user information, roles,
	 *         timestamp, message, and HTTP status code
	 * @throws InterruptedException if the thread is interrupted while processing the image
	 */
	@PatchMapping("/update/image")
    public ResponseEntity<HttpResponse> updateProfileImage(
    		Authentication authentication,
    		@RequestParam ("image") MultipartFile image
	) throws InterruptedException {
		
	    UserDto userDto = UserUtils.getAuthenticatedUserDto(authentication);
        log.info("Updating image for user ID: {}", userDto.getId());
        UserDto updatedUserDto = this.userService.updateImage(userDto, image);
    	this.eventPublisher.publishEvent(new NewUserEvent(userDto.getEmail(), EventType.PROFILE_PICTURE_UPDATE));

        HttpResponse response = HttpResponse.builder()
	            .data(Map.of(
	                    "user", updatedUserDto,
	                    "roles", userRoleService.getAllRoles()

	            ))
	            .timeStamp(LocalDateTime.now().toString())
	            .message("Profile image updated for user ID: " + updatedUserDto.getId())
	            .status(HttpStatus.OK)
	            .statusCode(HttpStatus.OK.value())
	            .build();
        log.info("MFA toggled successfully for user ID: {}", userDto.getId());
        return ResponseEntity.ok(response);
    }
	
	/**
	 * Retrieves the profile image file as a byte array.
	 * <p>
	 * This endpoint reads the image file located in the user's local
	 * "Downloads/images" directory and returns its content as a byte array.
	 * The file is identified by its {@code fileName} path variable.
	 * </p>
	 *
	 * @param fileName the name of the image file to retrieve
	 * @return a byte array containing the contents of the requested image file
	 * @throws Exception if an error occurs while reading the file, such as
	 *                   the file not existing or lacking read permissions
	 */
	@GetMapping(value = "/image/{fileName}", produces = MediaType.IMAGE_PNG_VALUE)
	public byte [] getProfileImage(@PathVariable String fileName) throws Exception {
		return Files.readAllBytes(Paths.get(System.getProperty("user.home") + "/Downloads/images/" + fileName));
	}

	/**
	 * Handles the refresh token request and generates a new refresh token if the provided
	 * Authorization header contains a valid token.
	 *
	 * <p>This endpoint extracts the token from the request header, validates it, retrieves
	 * the associated user, and returns a new refresh token. If the token is missing or invalid,
	 * an error response is returned.</p>
	 *
	 * @param request the incoming HTTP servlet request containing the Authorization header
	 * @return a {@link ResponseEntity} containing an {@link HttpResponse} with user data and a new refresh token,
	 *         or an error message if validation fails
	 */
	@GetMapping("/refresh/token")
	public ResponseEntity<HttpResponse> refreshToken(HttpServletRequest request) {

	    // Validación del header
	    String authorizationHeader = request.getHeader(org.springframework.http.HttpHeaders.AUTHORIZATION);
        String token = authorizationHeader.substring(TOKEN_PREFIX.length());

	    boolean headerValid = isHeaderTokenValid(request, token);

	    if (headerValid) {

	        Long userId = tokenProvider.getSubject(token, request);
	        log.debug("Extracted user id from token: {}", userId);

	        UserDto user = UserDtoMapper.fromUser(this.userService.getUserById(userId));
	        log.debug("User retrieved successfully with id: {}", userId);
	        
	        Map<String, Object> data = new java.util.HashMap<>();
	        data.put("user", user);
	        data.put("access_token", tokenProvider.createAccessToken(getUserPrincipal(user)));
	        data.put("refresh_token", token);

	        HttpResponse responseBody = HttpResponse.builder()
	                .timeStamp(java.time.LocalDateTime.now().toString())
	                .data(data)
	                .message("Token refreshed")
	                .status(org.springframework.http.HttpStatus.OK)
	                .statusCode(org.springframework.http.HttpStatus.OK.value())
	                .build();

	        return ResponseEntity.ok(responseBody);

	    } else {

	        HttpResponse responseBody = HttpResponse.builder()
	                .timeStamp(java.time.LocalDateTime.now().toString())
	                .reason("Refresh Token missing or invalid")
	                .developerMessage("Refresh Token missing or invalid")
	                .status(org.springframework.http.HttpStatus.BAD_REQUEST)
	                .statusCode(org.springframework.http.HttpStatus.BAD_REQUEST.value())
	                .build();

	        return ResponseEntity.badRequest().body(responseBody);
	    }
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
     * Retrieves a paginated list of events associated with the authenticated user.
     *
     * <p>This endpoint allows the client to request user-specific events using pagination
     * parameters. The events are sorted in descending order by their creation timestamp.
     * The authenticated user's identity is resolved through the provided {@link Authentication}
     * object.</p>
     *
     * @param authentication the authentication object containing the currently authenticated user
     * @param page the page number to retrieve (0-based index); defaults to {@code 0}
     * @param size the number of records per page; defaults to {@code 10}
     *
     * @return a {@link ResponseEntity} containing an {@link HttpResponse} with a paginated list
     *         of {@link UserEventResponseDto} objects under the {@code "events"} key
     *
     * @apiNote The response includes metadata such as total pages, total elements, and flags
     *          indicating whether the current page is the first or last page.
     *
     * @see UserUtils#getAuthenticatedUserDto(Authentication)
     * @see org.springframework.data.domain.Page
     * @see UserEventResponseDto
     */

    @GetMapping("/events")
    public ResponseEntity<HttpResponse> getUserEvents(
            Authentication authentication,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size
    ) {
        UserDto userDto = UserUtils.getAuthenticatedUserDto(authentication);
        log.info("Fetching events for user: {}, page: {}, size: {}", userDto.getId(), page, size);
        
        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        Page<UserEventResponseDto> eventsPage = this.eventService.getPagedEventsByUserId(userDto.getId(), pageable);

        HttpResponse response = HttpResponse.builder()
                .timeStamp(LocalDateTime.now().toString())
                .data(Map.of("events", eventsPage))
                .message("Events retrieved successfully")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build();

        return ResponseEntity.ok().body(response);
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

			var role = userRoleService.getRoleByUserId(user.getId());
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
	 * Authenticates a user with the given email and password while publishing login-related
	 * application events for auditing purposes.
	 *
	 * <p>Flow:
	 * <ul>
	 *   <li>Publishes a {@code LOGIN_ATTEMPT} event if the email exists.</li>
	 *   <li>Attempts authentication via {@link AuthenticationManager}.</li>
	 *   <li>On success: returns the authenticated {@link UserDto} and publishes
	 *       {@code LOGIN_ATTEMPT_SUCCESS} if MFA is disabled.</li>
	 *   <li>On failure: publishes {@code LOGIN_ATTEMPT_FAILURE}, logs the error, and throws an {@link ApiException}.</li>
	 * </ul>
	 *
	 * @param email    the user's email
	 * @param password the user's password
	 * @return the authenticated {@link UserDto}
	 * @throws ApiException if authentication fails
	 */
    private UserDto authenticate(String email, String password) {
        log.debug("Starting authentication process for user: {}", email);
        Authentication authentication = null;

        try {
        	// There is a valid email for the authentication try
        	if(null != this.userService.getUserByEmail(email)) {
            	this.eventPublisher.publishEvent(new NewUserEvent(email, EventType.LOGIN_ATTEMPT));
        	}
            authentication = authenticationManager.authenticate(
                    unauthenticated(email, password));
            UserDto loggedInUserDto = UserUtils.getLoggedInUserDto(authentication);
            
			if (!loggedInUserDto.isUsingMfa()) {
	        	this.eventPublisher.publishEvent(new NewUserEvent(email, EventType.LOGIN_ATTEMPT_SUCCESS));
	            log.info("User '{}' successfully authenticated", email);
			}

            return loggedInUserDto;

        } catch (Exception e) {
        	// Publish login attempt failure event
        	this.eventPublisher.publishEvent(new NewUserEvent(email, EventType.LOGIN_ATTEMPT_FAILURE));
            log.error("Authentication failed for user '{}': {}", email, e.getMessage(), e);
            ExceptionUtils.processError(request, response, e);
            log.debug("ApiException thrown for user '{}'", email);
            throw new ApiException(e.getMessage());
        }

    }

}
