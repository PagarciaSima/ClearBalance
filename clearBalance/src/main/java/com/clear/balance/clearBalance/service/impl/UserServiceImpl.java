package com.clear.balance.clearBalance.service.impl;

import static org.springframework.web.servlet.support.ServletUriComponentsBuilder.fromCurrentContextPath;

import java.util.Collection;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.clear.balance.clearBalance.domain.AccountVerification;
import com.clear.balance.clearBalance.domain.Role;
import com.clear.balance.clearBalance.domain.User;
import com.clear.balance.clearBalance.domain.UserRole;
import com.clear.balance.clearBalance.dto.UserDto;
import com.clear.balance.clearBalance.dtoMapper.UserDtoMapper;
import com.clear.balance.clearBalance.enumeration.RoleType;
import com.clear.balance.clearBalance.enumeration.VerificationType;
import com.clear.balance.clearBalance.exeception.ApiException;
import com.clear.balance.clearBalance.repository.AccountVerificationRepository;
import com.clear.balance.clearBalance.repository.RoleRepository;
import com.clear.balance.clearBalance.repository.UserRepository;
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
	private final BCryptPasswordEncoder encoder;
	private final EmailService emailService;
	private final AccountVerificationRepository accountVerificationRepository;

	@Override
	@Transactional
	public UserDto create(User user) {
		try {

			// 1. Verificar si el correo ya existe
			if (userRepository.existsByEmail(user.getEmail().trim().toLowerCase())) {
				throw new ApiException("Email already in use. Please use a different email and try again.");
			}

			// 2. Guardar usuario con datos básicos
			user.setPassword(encoder.encode(user.getPassword()));
			user.setEnabled(false);
			user.setNotLocked(true);
			userRepository.save(user);

			// 3. Asignar rol por defecto
			Role defaultRole = roleRepository.findByName(RoleType.ROLE_USER.name())
					.orElseThrow(() -> new ApiException("Default role not found."));
			UserRole userRole = new UserRole();
			userRole.setUser(user);
			userRole.setRole(defaultRole);
			user.getUserRoles().add(userRole);

			userRepository.save(user);

			// 4. Generar URL de verificación
			String verificationUrl = getVerificationUrl(UUID.randomUUID().toString(),
					VerificationType.ACCOUNT.getType());

			// 5. Guardar la verificación y enviar el correo
			AccountVerification verification = AccountVerification.builder()
				    .user(user)
				    .url(verificationUrl)
				    .build();

				accountVerificationRepository.save(verification);
			// sendEmail(user.getFirstName(), user.getEmail(), verificationUrl,
			// VerificationType.ACCOUNT);

			log.info("User created successfully: {}", user.getEmail());
			return UserDtoMapper.fromUser(user);
		} catch (Exception e) {
			log.error("Error creating user: {}", e.getMessage());
			throw new ApiException("An unexpected error ocurred: " + e.getMessage());
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
	public User getUserByEmail(String email) {
		return userRepository.findByEmail(email)
				.orElseThrow(() -> new ApiException("User not found with email: " + email));
	}

	private String getVerificationUrl(String key, String type) {
		return fromCurrentContextPath().path("/user/verify/" + type + "/" + key).toUriString();
	}

	private void sendEmail(String firstName, String email, String verificationUrl, VerificationType verificationType) {
		CompletableFuture.runAsync(
				() -> emailService.sendVerificationEmail(firstName, email, verificationUrl, verificationType));

	}

}
