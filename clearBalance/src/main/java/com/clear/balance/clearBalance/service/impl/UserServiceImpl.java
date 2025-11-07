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
import com.clear.balance.clearBalance.service.EmailService;
import com.clear.balance.clearBalance.service.UserService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Slf4j
@Service
public class UserServiceImpl implements UserService {
	private static final String DATE_FORMAT = "yyyy-MM-dd HH:mm:ss";
	private final UserRepository userRepository;
	private final RoleRepository roleRepository;
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
	 *   <li>Validates that the provided email address is not already in use.</li>
	 *   <li>Encodes the user's password and saves basic user information.</li>
	 *   <li>Assigns the default role {@code ROLE_USER} to the new user.</li>
	 *   <li>Generates an account verification URL and saves the verification entity.</li>
	 *   <li>Optionally sends a verification email (currently commented out).</li>
	 * </ol>
	 * <p>
	 * The method is transactional — if any step fails, all previous changes are rolled back.
	 *
	 * @param user The {@link User} entity containing the new user’s information.
	 * @return A {@link UserDto} representation of the newly created user.
	 * @throws ApiException If the email already exists or an unexpected error occurs.
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
	        AccountVerification verification = AccountVerification.builder()
	                .user(user)
	                .url(verificationUrl)
	                .build();
	        accountVerificationRepository.save(verification);
	        log.debug("Account verification entity saved for user: {}", user.getEmail());

	        // Optional: send verification email
	        // sendEmail(user.getFirstName(), user.getEmail(), verificationUrl, VerificationType.ACCOUNT);

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


	@Override
	public Collection<User> list(int page, int pageSize) {
		return userRepository.findAll(); // luego se puede mejorar con Pageable
	}

	@Override
	public User get(Long id) {
		return userRepository.findById(id).orElseThrow(() -> new ApiException("User not found with id: " + id));
	}

	@Override
	public User update(User user) {
		if (!userRepository.existsById(user.getId())) {
			throw new ApiException("User not found with id: " + user.getId());
		}
		return userRepository.save(user);
	}

	@Override
	public Boolean delete(Long id) {
		if (!userRepository.existsById(id))
			return false;
		userRepository.deleteById(id);
		return true;
	}

	@Override
	public UserDto getUserByEmail(String email) {
	    User user = userRepository.findByEmail(email)
	            .orElseThrow(() -> new ApiException("User not found with email: " + email));
	    return UserDtoMapper.fromUser(user);
	}

	private String getVerificationUrl(String key, String type) {
		return fromCurrentContextPath().path("/user/verify/" + type + "/" + key).toUriString();
	}

	private void sendEmail(String firstName, String email, String verificationUrl, VerificationType verificationType) {
		CompletableFuture.runAsync(
				() -> emailService.sendVerificationEmail(firstName, email, verificationUrl, verificationType));

	}

	@Override
	public void sendVerificationCode(UserDto userDto) {
	    LocalDateTime expirationDate = LocalDateTime.now().plusDays(1);
	    String verificationCode = RandomStringUtils.randomAlphabetic(8).toUpperCase();

	    User user = userRepository.findByEmail(userDto.getEmail())
	            .orElseThrow(() -> new ApiException("User not found with email: " + userDto.getEmail()));

	    twoFactorVerificationRepository.deleteByUserId(user.getId());

	    TwoFactorVerification verification = TwoFactorVerification.builder()
	            .userId(user.getId())
	            .code(verificationCode)
	            .expirationDate(expirationDate)
	            .build();

	    twoFactorVerificationRepository.save(verification);
	    smsUtils.sendSMS(user.getPhone(), "From: ClearBalance \nVerification code \n" + verificationCode); 
	}



}
