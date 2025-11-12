package com.clear.balance.clearBalance.service.impl;

import static org.springframework.web.servlet.support.ServletUriComponentsBuilder.fromCurrentContextPath;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.clear.balance.clearBalance.Utils.SmsUtils;
import com.clear.balance.clearBalance.domain.AccountVerification;
import com.clear.balance.clearBalance.domain.Role;
import com.clear.balance.clearBalance.domain.TwoFactorVerification;
import com.clear.balance.clearBalance.domain.User;
import com.clear.balance.clearBalance.domain.UserRole;
import com.clear.balance.clearBalance.dto.UserDto;
import com.clear.balance.clearBalance.dtoMapper.UserDtoMapper;
import com.clear.balance.clearBalance.enumeration.RoleType;
import com.clear.balance.clearBalance.enumeration.VerificationType;
import com.clear.balance.clearBalance.exeception.ApiException;
import com.clear.balance.clearBalance.repository.AccountVerificationRepository;
import com.clear.balance.clearBalance.repository.RoleRepository;
import com.clear.balance.clearBalance.repository.TwoFactorVerificationRepository;
import com.clear.balance.clearBalance.repository.UserRepository;
import com.clear.balance.clearBalance.repository.UserRoleRepository;
import com.clear.balance.clearBalance.service.EmailService;
import com.clear.balance.clearBalance.service.UserService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Slf4j
@Service
public class UserServiceImpl implements UserService {
	private final UserRepository userRepository;
	private final RoleRepository roleRepository;
	private final RoleServiceImpl roleServiceImpl;
	private final BCryptPasswordEncoder encoder;
	private final EmailService emailService;
	private final AccountVerificationRepository accountVerificationRepository;
	private final TwoFactorVerificationRepository twoFactorVerificationRepository;
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
			user.setEnabled(true);
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
	public User get(Long id) {
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
}
