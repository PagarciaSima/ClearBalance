package com.clear.balance.clearBalance.controller;

import static org.springframework.web.servlet.support.ServletUriComponentsBuilder.fromCurrentContextPath;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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

	private final UserService userService;
	private final AuthenticationManager authenticationManager;
	private final TokenProvider tokenProvider;
	private final RoleService roleService;

	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody(required = true) @Valid LoginRequestDto loginRequestDto) {
		authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequestDto.getEmail(), loginRequestDto.getPassword()));
		UserDto userDto = userService.getUserDtoByEmail(loginRequestDto.getEmail());
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
					.body(HttpResponse.builder().timeStamp(LocalDateTime.now().toString()).data(Map.of("user", userDto))
							.message(String.format("User account created for user %s", user.getFirstName()))
							.status(HttpStatus.CREATED).statusCode(HttpStatus.CREATED.value()).build());

			log.info("Registration completed successfully for email: {}", user.getEmail());
			return response;

		} catch (Exception e) {
			log.error("Error while registering user '{}': {}", user.getEmail(), e.getMessage(), e);
			throw e; // Let global exception handler process it
		}
	}

	@GetMapping("/verify/code/{email}/{code}")
	public ResponseEntity<HttpResponse> verifyCode(@PathVariable String email, @PathVariable String code) {

		UserDto user = userService.verifyCode(email, code);
		return ResponseEntity.ok().body(HttpResponse.builder().timeStamp(LocalDateTime.now().toString())
				.data(Map.of("user", user, "access_token", tokenProvider.createAccessToken(getUserPrincipal(user)),
						"refresh_token", tokenProvider.createRefreshToken(getUserPrincipal(user))))
				.message("Login successful").status(HttpStatus.OK).statusCode(HttpStatus.OK.value()).build());
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
		return ResponseEntity.ok().body(HttpResponse.builder().timeStamp(LocalDateTime.now().toString())
				.data(Map.of("user", user, "access_token", tokenProvider.createAccessToken(getUserPrincipal(user)),
						"refresh_token", tokenProvider.createRefreshToken(getUserPrincipal(user))))
				.message("Login successful").status(HttpStatus.OK).statusCode(HttpStatus.OK.value()).build());
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

			var userPrincipal = new UserPrincipal(UserDtoMapper.toUser(userDto), role.getPermission());

			log.info("Successfully created UserPrincipal for user: {}", user.getEmail());
			return userPrincipal;
		} catch (Exception e) {
			log.error("Error while creating UserPrincipal for user {}: {}", user.getEmail(), e.getMessage(), e);
			throw e;
		}
	}
}
