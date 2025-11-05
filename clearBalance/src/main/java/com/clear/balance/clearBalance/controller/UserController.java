package com.clear.balance.clearBalance.controller;

import static org.springframework.web.servlet.support.ServletUriComponentsBuilder.fromCurrentContextPath;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.clear.balance.clearBalance.domain.HttpResponse;
import com.clear.balance.clearBalance.domain.User;
import com.clear.balance.clearBalance.dto.UserDto;
import com.clear.balance.clearBalance.service.UserService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
@Slf4j
public class UserController {

	private final UserService userService;

	@PostMapping("/register")
	public ResponseEntity<HttpResponse> saveUser(@RequestBody @Valid User user) throws InterruptedException {
		UserDto userDto = userService.create(user);
		return ResponseEntity.created(getUri())
				.body(HttpResponse.builder().timeStamp(LocalDateTime.now().toString()).data(Map.of("user", userDto))
						.message(String.format("User account created for user %s", user.getFirstName()))
						.status(HttpStatus.CREATED).statusCode(HttpStatus.CREATED.value()).build());
	}

	private URI getUri() {
		return URI.create(fromCurrentContextPath().path("/user/get/<userId>").toUriString());
	}

}
