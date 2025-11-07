package com.clear.balance.clearBalance.configuration;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.clear.balance.clearBalance.handler.CustomAccessDeniedHandler;
import com.clear.balance.clearBalance.handler.CustomAuthenticationEntryPoint;
import com.clear.balance.clearBalance.service.impl.CustomUserDetailsServiceImpl;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

	public static final String[] PUBLIC_URLS = { "/user/verify/password/**", "/user/login/**", "/user/verify/code/**",
			"/user/register/**", "/user/resetpassword/**", "/user/verify/account/**", "/user/refresh/token/**",
			"/user/image/**", "/user/new/password/**" };

	private static final int STRENGHT = 12;
	private final CustomAccessDeniedHandler customAccessDeniedHandler;
	private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
	private final CustomUserDetailsServiceImpl customUserDetailsServiceImpl;

	@Bean
	BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder(STRENGHT);
	}

	@Bean
	AuthenticationManager authenticationManager() {
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
		authProvider.setUserDetailsService(customUserDetailsServiceImpl);
		authProvider.setPasswordEncoder(passwordEncoder());
		return new ProviderManager(authProvider);
	}

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http.csrf(csrf -> csrf.disable()).cors(withDefaults());
		http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		http.authorizeHttpRequests(request -> request.requestMatchers(PUBLIC_URLS).permitAll());
		http.authorizeHttpRequests(request -> request.requestMatchers(HttpMethod.OPTIONS).permitAll());
		http.authorizeHttpRequests(request -> request.requestMatchers(HttpMethod.DELETE, "/user/delete/**")
				.hasAnyAuthority("DELETE:USER"));
		http.authorizeHttpRequests(request -> request.requestMatchers(HttpMethod.DELETE, "/customer/delete/**")
				.hasAnyAuthority("DELETE:CUSTOMER"));
		// Manages unauthorized access attempts / 403
		http.exceptionHandling(exception -> exception.accessDeniedHandler(customAccessDeniedHandler)
				// Manages unauthenticated access attempts / 401
				.authenticationEntryPoint(customAuthenticationEntryPoint));
		http.authorizeHttpRequests(request -> request.anyRequest().authenticated());
		return http.build();
	}
}
