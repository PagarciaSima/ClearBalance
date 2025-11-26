package com.clear.balance.clearBalance.service.impl;

import static org.springframework.web.servlet.support.ServletUriComponentsBuilder.fromCurrentContextPath;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.clear.balance.clearBalance.Utils.SmsUtils;
import com.clear.balance.clearBalance.domain.AccountVerification;
import com.clear.balance.clearBalance.domain.ResetPasswordVerification;
import com.clear.balance.clearBalance.domain.Role;
import com.clear.balance.clearBalance.domain.TwoFactorVerification;
import com.clear.balance.clearBalance.domain.User;
import com.clear.balance.clearBalance.domain.UserRole;
import com.clear.balance.clearBalance.dto.UpdateFormDto;
import com.clear.balance.clearBalance.dto.UserDto;
import com.clear.balance.clearBalance.dtoMapper.UserDtoMapper;
import com.clear.balance.clearBalance.enumeration.RoleType;
import com.clear.balance.clearBalance.enumeration.VerificationType;
import com.clear.balance.clearBalance.exeception.ApiException;
import com.clear.balance.clearBalance.repository.AccountVerificationRepository;
import com.clear.balance.clearBalance.repository.ResetPasswordVerificationRepository;
import com.clear.balance.clearBalance.repository.RoleRepository;
import com.clear.balance.clearBalance.repository.TwoFactorVerificationRepository;
import com.clear.balance.clearBalance.repository.UserRepository;
import com.clear.balance.clearBalance.service.EmailService;
import com.clear.balance.clearBalance.service.UserService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Slf4j
@Service
public class UserServiceImpl implements UserService {
	private final UserRepository userRepository;
	private final RoleRepository roleRepository;
	private final RoleServiceImpl roleServiceImpl;
	private final PasswordEncoder encoder;
	private final EmailService emailService;
	private final AccountVerificationRepository accountVerificationRepository;
	private final TwoFactorVerificationRepository twoFactorVerificationRepository;
	private final ResetPasswordVerificationRepository resetPasswordVerificationRepository;
	private final SmsUtils smsUtils;

	/**
	 * Creates a new user in the system.
	 * <p>
	 * This method performs the following operations:
	 * <ol>
	 * <li>Validates that the provided email address is not already in use.</li>
	 * <li>Encodes the user's password and saves basic user information.</li>
	 * <li>Assigns the default role {@code ROLE_USER} to the new user.</li>
	 * <li>Generates an account verification URL and saves the verification
	 * entity.</li>
	 * <li>Optionally sends a verification email (currently commented out).</li>
	 * </ol>
	 * <p>
	 * The method is transactional — if any step fails, all previous changes are
	 * rolled back.
	 *
	 * @param user The {@link User} entity containing the new user’s information.
	 * @return A {@link UserDto} representation of the newly created user.
	 * @throws ApiException If the email already exists or an unexpected error
	 *                      occurs.
	 */
	@Override
	@Transactional
	public UserDto create(User user) {
		log.info("Starting user creation process for email: {}", user.getEmail());

		try {
			// 1. Verify if email already exists
			if (userRepository.existsByEmail(user.getEmail().trim().toLowerCase())) {
				log.warn("Attempt to create user with existing email: {}", user.getEmail());
				throw new ApiException("Email already in use. Please use a different email and try again.");
			}

			// 2. Save user with basic data
			log.debug("Encoding password and saving basic user information for: {}", user.getEmail());
			user.setPassword(encoder.encode(user.getPassword()));
			user.setEnabled(false);
			user.setNotLocked(true);
			userRepository.save(user);

			// 3. Assign default role
			log.debug("Assigning default role '{}' to user: {}", RoleType.ROLE_USER.name(), user.getEmail());
			Role defaultRole = roleRepository.findByName(RoleType.ROLE_USER.name())
					.orElseThrow(() -> new ApiException("Default role not found."));
			UserRole userRole = new UserRole();
			userRole.setUser(user);
			userRole.setRole(defaultRole);
			user.setUserRole(userRole);
			userRepository.save(user);

			// 4. Generate verification URL
			String verificationUrl = getVerificationUrl(UUID.randomUUID().toString(),
					VerificationType.ACCOUNT.getType());
			log.debug("Generated verification URL for {}: {}", user.getEmail(), verificationUrl);

			// 5. Save verification and send email
			AccountVerification verification = AccountVerification.builder().user(user).url(verificationUrl).build();
			accountVerificationRepository.save(verification);
			log.debug("Account verification entity saved for user: {}", user.getEmail());

			// Optional: send verification email
			// sendEmail(user.getFirstName(), user.getEmail(), verificationUrl,
			// VerificationType.ACCOUNT);

			log.info("User created successfully: {}", user.getEmail());
			return UserDtoMapper.fromUser(user);

		} catch (ApiException e) {
			log.error("Business validation error while creating user '{}': {}", user.getEmail(), e.getMessage());
			throw e;
		} catch (Exception e) {
			log.error("Unexpected error while creating user '{}': {}", user.getEmail(), e.getMessage(), e);
			throw new ApiException("An unexpected error occurred: " + e.getMessage());
		}
	}

	/**
	 * Retrieves a paginated list of all users in the system.
	 * <p>
	 * This method is intended to return a collection of {@link User} entities.
	 * Note: Currently, the implementation ignores pagination parameters (page, pageSize)
	 * and returns all users via {@code userRepository.findAll()}.
	 *
	 * @param page The requested page number (0-indexed).
	 * @param pageSize The number of users to retrieve per page.
	 * @return A {@link Collection} of {@link User} entities.
	 */
	@Override
	public Collection<User> list(int page, int pageSize) {
	    // Log the start of the operation, including pagination parameters
	    log.info("Fetching list of users. Page: {}, PageSize: {}", page, pageSize);
	    Collection<User> users = userRepository.findAll();
	    // Log the result count
	    log.info("Successfully retrieved {} users.", users.size());

	    return users;
	}

	/**
	 * Retrieves a user by their ID.
	 *
	 * @param id the ID of the user to retrieve
	 * @return the User entity
	 * @throws ApiException if no user is found with the provided ID
	 */
	@Override
	public User getUserById(Long id) {
		log.info("Fetching user with ID: {}", id);

		User user = userRepository.findById(id).orElseThrow(() -> {
			log.error("User not found with ID: {}", id);
			return new ApiException("User not found with id: " + id);
		});

		log.info("User retrieved: ID={}, email={}", user.getId(), user.getEmail());
		return user;
	}

	/**
	 * Updates an existing user.
	 *
	 * @param user the User entity containing updated information
	 * @return the updated User entity
	 * @throws ApiException if the user does not exist
	 */
	@Override
	public User update(User user) {
		log.info("Attempting to update user with ID: {}", user.getId());

		if (!userRepository.existsById(user.getId())) {
			log.error("Cannot update. User not found with ID: {}", user.getId());
			throw new ApiException("User not found with id: " + user.getId());
		}

		User updatedUser = userRepository.save(user);
		log.info("User updated successfully: ID={}, email={}", updatedUser.getId(), updatedUser.getEmail());
		return updatedUser;
	}

	/**
	 * Deletes a user by their ID.
	 *
	 * @param id the ID of the user to delete
	 * @return true if the user existed and was deleted, false otherwise
	 */
	@Override
	public Boolean delete(Long id) {
		log.info("Attempting to delete user with ID: {}", id);

		if (!userRepository.existsById(id)) {
			log.warn("User with ID {} does not exist", id);
			return false;
		}

		userRepository.deleteById(id);
		log.info("User with ID {} has been deleted", id);
		return true;
	}

	/**
	 * Retrieves a user by their email address.
	 *
	 * @param email the email of the user to retrieve
	 * @return a UserDto representing the user
	 * @throws ApiException if no user is found with the provided email
	 */
	@Override
	public UserDto getUserDtoByEmail(String email) {
		log.info("Fetching user by email: {}", email);

		User user = userRepository.findByEmail(email).orElseThrow(() -> {
			log.error("User not found with email: {}", email);
			return new ApiException("User not found with email: " + email);
		});

		log.info("User found: ID={}, email={}", user.getId(), user.getEmail());
		return UserDtoMapper.fromUser(user, roleServiceImpl.getRoleByUserId(user.getId()));
	}

	/**
	 * Retrieves a user by their email address.
	 *
	 * @param email the email of the user to retrieve
	 * @return a UserDto representing the user
	 * @throws ApiException if no user is found with the provided email
	 */
	@Override
	public User getUserByEmail(String email) {
		log.info("Fetching user by email: {}", email);

		User user = userRepository.findByEmail(email).orElseThrow(() -> {
			log.error("User not found with email: {}", email);
			return new ApiException("User not found with email: " + email);
		});

		log.info("User found: ID={}, email={}", user.getId(), user.getEmail());
		return user;
	}

	/**
	 * Constructs a verification URL for a given key and type.
	 *
	 * @param key  the verification key
	 * @param type the type of verification (e.g., "email", "phone")
	 * @return the full verification URL as a String
	 */
	private String getVerificationUrl(String key, String type) {
		String url = fromCurrentContextPath().path("/user/verify/" + type + "/" + key).toUriString();
		log.debug("Generated verification URL: {}", url);
		return url;
	}

	/**
	 * Sends a verification email asynchronously.
	 *
	 * @param firstName        the first name of the user
	 * @param email            the email address to send the verification to
	 * @param verificationUrl  the verification URL to include in the email
	 * @param verificationType the type of verification being sent
	 */
	private void sendEmail(String firstName, String email, String verificationUrl, VerificationType verificationType) {
		CompletableFuture.runAsync(
				() -> emailService.sendVerificationEmail(firstName, email, verificationUrl, verificationType));
	}

	/**
	 * Sends a verification code via SMS to the user's phone and stores it in the
	 * database.
	 * <p>
	 * This method generates a random 8-character alphanumeric verification code,
	 * sets its expiration date to 1 day from now, deletes any existing verification
	 * entries for the user, saves the new verification code, and sends it via SMS.
	 *
	 * @param userDto the user data transfer object containing the user's email
	 * @throws ApiException if no user is found with the provided email
	 */
	@Transactional
	@Override
	public void sendVerificationCode(UserDto userDto) {
		log.info("Generating verification code for user: {}", userDto.getEmail());

		LocalDateTime expirationDate = LocalDateTime.now().plusDays(1);
		String verificationCode = RandomStringUtils.randomAlphabetic(8).toUpperCase();
		log.debug("Generated verification code: {}", verificationCode);

		User user = userRepository.findByEmail(userDto.getEmail()).orElseThrow(() -> {
			log.error("User not found with email: {}", userDto.getEmail());
			return new ApiException("User not found with email: " + userDto.getEmail());
		});

		log.info("Deleting existing two-factor verifications for user ID: {}", user.getId());
		twoFactorVerificationRepository.deleteByUserId(user.getId());
		twoFactorVerificationRepository.flush();

		TwoFactorVerification verification = TwoFactorVerification.builder().userId(user.getId()).code(verificationCode)
				.expirationDate(expirationDate).build();

		twoFactorVerificationRepository.save(verification);
		log.info("Saved new verification code for user ID: {}", user.getId());

		// smsUtils.sendSMS(user.getPhone(), "From: ClearBalance \nVerification code \n"
		// + verificationCode);
		log.info("Verification code: {}", verificationCode);

		log.info("Sent SMS verification code to phone: {}", user.getPhone());
	}
	
	/**
	 * Verifies a two-factor authentication code for a given user's email.
	 * <p>
	 * This method performs the following steps:
	 * <ol>
	 *   <li>Searches for the verification record by the provided code.</li>
	 *   <li>Checks if the verification code has expired.</li>
	 *   <li>Retrieves the user associated with the verification code.</li>
	 *   <li>Validates that the provided email matches the user's email.</li>
	 *   <li>If all checks pass, deletes the verification record and returns the user's DTO with roles.</li>
	 * </ol>
	 * <p>
	 * Logs relevant events including verification attempts, errors, and successful verification.
	 *
	 * @param email the email of the user to verify the code against
	 * @param code the verification code to validate
	 * @return a {@link UserDto} containing the user's information and roles
	 * @throws ApiException if the code is invalid, expired, or the email does not match
	 */
	@Override
	@Transactional
	public UserDto verifyCode(String email, String code) {
		log.info("Verifying code '{}' for user with email '{}'", code, email);

		// 1. Search verification by code
		TwoFactorVerification verification = twoFactorVerificationRepository.findByCode(code);
		if (verification == null) {
			log.error("Verification code '{}' not found", code);
			throw new ApiException("Code is invalid. Please try again.");
		}

		// 2. Check expiration
		if (verification.getExpirationDate().isBefore(LocalDateTime.now())) {
			log.warn("Verification code '{}' has expired", code);
			throw new ApiException("This code has expired. Please login again.");
		}

		// 3. Get user by ID
		User user = userRepository.findById(verification.getUserId())
				.orElseThrow(() -> new ApiException("User not found"));

		// 4. Check email matches
		if (!user.getEmail().equalsIgnoreCase(email)) {
			log.error("Email '{}' does not match the user for this code", email);
			throw new ApiException("Code is invalid. Please try again.");
		}

		twoFactorVerificationRepository.delete(verification);
		log.info("Verification code '{}' successfully verified for user '{}'", code, email);

		return UserDtoMapper.fromUser(user, roleServiceImpl.getRoleByUserId(user.getId()));
	}
	
	/**
	 * Resets the password process for the user associated with the given email.
	 * <p>
	 * This method performs the following steps:
	 * <ul>
	 *   <li>Retrieves the user by email and throws an {@link ApiException} if not found.</li>
	 *   <li>Deletes any previous {@link ResetPasswordVerification} entries for the user.</li>
	 *   <li>Generates a new password reset verification URL with a 24-hour expiration.</li>
	 *   <li>Saves the verification entity to the database.</li>
	 *   <li>(Optionally) Sends a password reset email to the user.</li>
	 * </ul>
	 * </p>
	 *
	 * @param email the email address of the user requesting the password reset
	 * @return a {@link UserDto} representing the user whose password reset was initiated
	 * @throws ApiException if no user exists with the provided email
	 */
	@Override
	@Transactional
	public UserDto resetPassword(String email) {
	    User user = this.getUserByEmail(email); 
	    if (user == null) {
	        throw new ApiException("There is no account for this email address: " + email);
	    }
	    
	    // Delete existing ResetPasswordVerification entries for the user
	    resetPasswordVerificationRepository.deleteByUserId(user.getId());
	    
	    LocalDateTime expirationDate = LocalDateTime.now().plusDays(1);
	    String verificationUrl = getVerificationUrl(UUID.randomUUID().toString(),
	            VerificationType.PASSWORD.getType());
	    
	    log.info("Verification URL for password reset: {}", verificationUrl);
	    
	    //Create & save ResetPasswordVerification
	    ResetPasswordVerification resetVerification = ResetPasswordVerification.builder()
	            .user(user)
	            .url(verificationUrl)
	            .expirationDate(expirationDate) 
	            .build();
	    
	    resetPasswordVerificationRepository.save(resetVerification);
	    
	    //Send email
	    // sendEmail(user.getFirstName(), user.getEmail(), verificationUrl, VerificationType.PASSWORD);
	    
	    log.info("Password reset initiated for user: {}", email);
	    return UserDtoMapper.fromUser(user);
	}

	/**
	 * Verifies the validity of a password reset request identified by the given key.
	 * <p>
	 * This method performs the following steps:
	 * <ul>
	 *   <li>Logs the received verification key.</li>
	 *   <li>Searches for a {@link ResetPasswordVerification} entry whose URL contains the key.</li>
	 *   <li>Throws an {@link ApiException} if no matching verification entry exists.</li>
	 *   <li>Checks whether the verification link has expired and deletes it if so,
	 *       throwing an {@link ApiException} to notify the client.</li>
	 *   <li>Retrieves the associated {@link User} when the key is valid and not expired.</li>
	 *   <li>Returns a {@link UserDto} mapped from the verified user.</li>
	 * </ul>
	 * </p>
	 *
	 * @param key the unique password reset verification key included in the reset URL
	 * @return a {@link UserDto} representing the user associated with the valid reset request
	 * @throws ApiException if the verification key is invalid or the reset link has expired
	 */
	@Override
	@Transactional
	public UserDto verifyPassword(String key) {
	    log.info("Verifying password reset key: {}", key);
	    
	    // Buscar por el UUID (parte final de la URL)
	    ResetPasswordVerification verification = resetPasswordVerificationRepository.findByUrlContaining(key)
	            .orElseThrow(() -> {
	                log.error("Invalid password reset key: {}", key);
	                return new ApiException("Invalid password reset link. Please request a new one.");
	            });
	    
	    // Verificar si ha expirado
	    if (verification.getExpirationDate().isBefore(LocalDateTime.now())) {
	        log.warn("Password reset link has expired for key: {}", key);
	        resetPasswordVerificationRepository.delete(verification);
	        throw new ApiException("This link has expired. Please request a new password reset.");
	    }
	    
	    User user = verification.getUser();
	    log.info("Password reset key verified successfully for user: {}", user.getEmail());
	    
	    return UserDtoMapper.fromUser(user);
	}

	/**
	 * Renews the user's password using a valid password reset verification key.
	 * <p>
	 * This method performs the following operations:
	 * <ul>
	 *   <li>Validates that the provided password and confirmation match.</li>
	 *   <li>Retrieves the corresponding {@link ResetPasswordVerification} using the reset key,
	 *       throwing an {@link ApiException} if the key is invalid.</li>
	 *   <li>Checks whether the reset link has expired, removing it and throwing an
	 *       {@link ApiException} if it is no longer valid.</li>
	 *   <li>Encodes and updates the user's password with the newly provided value.</li>
	 *   <li>Persists the updated user entity.</li>
	 *   <li>Deletes the verification entry after successful password renewal.</li>
	 *   <li>Returns a {@link UserDto} representing the updated user.</li>
	 * </ul>
	 * </p>
	 *
	 * @param key the unique verification key extracted from the password reset URL
	 * @param password the new password the user wants to set
	 * @param confirmPassword the confirmation of the new password, which must match {@code password}
	 * @return a {@link UserDto} representing the user whose password was successfully renewed
	 * @throws ApiException if passwords do not match, the key is invalid, or the reset link has expired
	 */
	@Override
	@Transactional
	public UserDto renewPassword(String key, String password, String confirmPassword) {
	    log.info("Renewing password for key: {}", key);
	    
	    // 1. Check if passwords match
	    if (!password.equals(confirmPassword)) {
	        log.error("Passwords do not match for key: {}", key);
	        throw new ApiException("Passwords do not match. Please try again.");
	    }
	    
	    // 2. Check that reset link exists
	    ResetPasswordVerification verification = resetPasswordVerificationRepository.findByUrlContaining(key)
	            .orElseThrow(() -> {
	                log.error("Invalid password reset key: {}", key);
	                return new ApiException("Invalid password reset link. Please request a new one.");
	            });
	    
	    // 3. Check if link has expired
	    if (verification.getExpirationDate().isBefore(LocalDateTime.now())) {
	        log.warn("Password reset link has expired for key: {}", key);
	        resetPasswordVerificationRepository.delete(verification);
	        throw new ApiException("This link has expired. Please request a new password reset.");
	    }
	    
	    // 4. Update user's old password with the new encoded password
	    User user = verification.getUser();
	    user.setPassword(encoder.encode(password));
	    userRepository.save(user);
	    
	    // 5. Delete the used verification entry
	    resetPasswordVerificationRepository.delete(verification);
	    
	    log.info("Password successfully renewed for user: {}", user.getEmail());
	    return UserDtoMapper.fromUser(user);
	}

	/**
	 * Verifies and activates a user account using the provided verification key.
	 * <p>
	 * This method handles the account activation flow after a user clicks the 
	 * verification link sent to their email during registration. It performs the following steps:
	 * <ul>
	 *   <li>Logs the received verification key.</li>
	 *   <li>Retrieves the corresponding {@link AccountVerification} entry using the key,
	 *       throwing an {@link ApiException} if the key is invalid.</li>
	 *   <li>Activates the user's account by setting {@code enabled = true} and persists the change.</li>
	 *   <li>Deletes the verification entry to prevent reuse.</li>
	 *   <li>Returns a {@link UserDto} representing the newly activated user.</li>
	 * </ul>
	 * </p>
	 *
	 * @param key the unique account verification key extracted from the activation URL
	 * @return a {@link UserDto} representing the user whose account has been successfully activated
	 * @throws ApiException if the verification key is invalid
	 */
	@Override
	@Transactional
	public UserDto verifyAccount(String key) {
	    log.info("Verifying account with key: {}", key);
	    
	    // Search by UUID key
	    AccountVerification verification = accountVerificationRepository.findByUrlContaining(key)
	            .orElseThrow(() -> {
	                log.error("Invalid account verification key: {}", key);
	                return new ApiException("Invalid account verification link. Please request a new one.");
	            });
	    
	    // Activar la cuenta del usuario
	    User user = verification.getUser();
	    user.setEnabled(true);
	    userRepository.save(user);
	    
	    // Delete verification entry
	    accountVerificationRepository.delete(verification);
	    
	    log.info("Account successfully verified and activated for user: {}", user.getEmail());
	    return UserDtoMapper.fromUser(user);
	}

	/**
	 * Updates the details of an existing user.
	 *
	 * <p>This method retrieves the user by the provided ID, validates whether the incoming
	 * email is already in use (if it was modified), updates the allowed user fields, and
	 * persists the changes in the database. The updated user is then mapped and returned
	 * as a {@link UserDto}.</p>
	 *
	 * <p>The method is executed within a transactional context to ensure that all operations
	 * are applied atomically. If any validation fails (such as attempting to use an email
	 * that already exists), an {@link ApiException} is thrown.</p>
	 *
	 * @param updateFormDto the DTO containing updated user information; must be valid and not null
	 * @return the updated user mapped as a {@link UserDto}
	 *
	 * @throws ApiException if the provided email is already associated with another user
	 * @throws jakarta.validation.ConstraintViolationException if validation of the DTO fails
	 * @throws InstanceNotFoundException if the user with the given ID does not exist
	 *
	 * @see UpdateFormDto
	 * @see UserDto
	 * @see UserDtoMapper
	 */
	@Override
	@Transactional
	public UserDto updateUserDetails(@Valid UpdateFormDto updateFormDto) {
	    log.info("Updating user with ID {}", updateFormDto.getId());

	    User existingUser = this.getUserById(updateFormDto.getId());

	    String incomingEmail = updateFormDto.getEmail().trim().toLowerCase();
	    if (!incomingEmail.equalsIgnoreCase(existingUser.getEmail())) {
	        if (userRepository.existsByEmail(incomingEmail)) {
	            throw new ApiException("Email already in use");
	        }
	        existingUser.setEmail(incomingEmail);
	    }

	    existingUser.setFirstName(updateFormDto.getFirstName());
	    existingUser.setLastName(updateFormDto.getLastName());
	    existingUser.setPhone(updateFormDto.getPhone());
	    existingUser.setAddress(updateFormDto.getAddress());
	    existingUser.setTitle(updateFormDto.getTitle());
	    existingUser.setBio(updateFormDto.getBio());

	    User savedUser = userRepository.save(existingUser);

	    log.info("User updated successfully with ID {}", savedUser.getId());

	    return UserDtoMapper.fromUser(savedUser);
	}

}
