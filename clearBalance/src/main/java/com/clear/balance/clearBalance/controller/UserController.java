package com.clear.balance.clearBalance.controller;

import static org.springframework.web.servlet.support.ServletUriComponentsBuilder.fromCurrentContextPath;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.clear.balance.clearBalance.domain.HttpResponse;
import com.clear.balance.clearBalance.domain.User;
import com.clear.balance.clearBalance.dto.LoginRequestDto;
import com.clear.balance.clearBalance.dto.UserDto;
import com.clear.balance.clearBalance.service.UserService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * REST controller for managing user-related operations such as registration.
 * <p>
 * Provides endpoints for creating and managing user accounts.
 * Uses {@link UserService} to handle business logic.
 */
@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
@Slf4j
public class UserController {

	private final UserService userService;
    private final AuthenticationManager authenticationManager;

	@PostMapping("/login")
    public ResponseEntity<HttpResponse> login(@RequestBody @Valid LoginRequestDto loginRequestDto) {
		authenticationManager
				.authenticate(new UsernamePasswordAuthenticationToken(loginRequestDto.getEmail(), loginRequestDto.getPassword()));
		UserDto userDto = userService.getUserByEmail(loginRequestDto.getEmail());
		return userDto.isUsingMfa() ? sendVerificationCode(userDto) : sendResponse(userDto);
	}

	/**
     * Registers a new user in the system.
     * <p>
     * This endpoint accepts a {@link User} object, delegates the creation process to
     * {@link UserService#create(User)}, and returns an HTTP response containing
     * the created user information.
     *
     * @param user The {@link User} entity to be registered.
     * @return A {@link ResponseEntity} containing a {@link HttpResponse} with user details.
     * @throws InterruptedException if the thread is interrupted during execution (for simulation or delay purposes).
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
                    .body(HttpResponse.builder()
                            .timeStamp(LocalDateTime.now().toString())
                            .data(Map.of("user", userDto))
                            .message(String.format("User account created for user %s", user.getFirstName()))
                            .status(HttpStatus.CREATED)
                            .statusCode(HttpStatus.CREATED.value())
                            .build());

            log.info("Registration completed successfully for email: {}", user.getEmail());
            return response;

        } catch (Exception e) {
            log.error("Error while registering user '{}': {}", user.getEmail(), e.getMessage(), e);
            throw e; // Let global exception handler process it
        }
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
                .body(HttpResponse.builder()
                        .timeStamp(LocalDateTime.now().toString())
                        .data(Map.of("user", user))
                        .message("Login successful")
                        .status(HttpStatus.OK)
                        .statusCode(HttpStatus.OK.value())
                        .build());
	}

	private ResponseEntity<HttpResponse> sendResponse(UserDto user) {
        return ResponseEntity.ok()
                .body(HttpResponse.builder()
                        .timeStamp(LocalDateTime.now().toString())
                        .data(Map.of("user", user))
                        .message("Login successful")
                        .status(HttpStatus.OK)
                        .statusCode(HttpStatus.OK.value())
                        .build());
    }


}
