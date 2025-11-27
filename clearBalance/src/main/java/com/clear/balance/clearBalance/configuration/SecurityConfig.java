package com.clear.balance.clearBalance.configuration;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.clear.balance.clearBalance.filter.CustomAuthorizationFilter;
import com.clear.balance.clearBalance.handler.CustomAccessDeniedHandler;
import com.clear.balance.clearBalance.handler.CustomAuthenticationEntryPoint;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {


	public static final String[] PUBLIC_URLS = {
		    "/user/verify/password/**",
		    "/user/login/**",
		    "/user/verify/code/**",
		    "/user/register/**",
		    "/user/resetpassword/**",
		    "/user/verify/account/**",
		    "/user/refresh/token/**",
		    "/user/image/**",
		    "/user/new/password/**",

		    // Swagger / OpenAPI
		    "/swagger-ui.html",
		    "/swagger-ui/**",
		    "/v3/api-docs/**"
		};

	public static final List<String> ALLOWED_METHODS =
	            List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH");
	private final CustomAccessDeniedHandler customAccessDeniedHandler;
	private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    private final CustomAuthorizationFilter customAuthorizationFilter;

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	    http
	        .csrf(AbstractHttpConfigurer::disable)
	        .cors(configure -> configure.configurationSource(corsConfigurationSource()))
	        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
	        .authorizeHttpRequests(request -> request
	            .requestMatchers(PUBLIC_URLS).permitAll()
	            .requestMatchers(HttpMethod.OPTIONS).permitAll()
	            .requestMatchers(HttpMethod.DELETE, "/user/delete/**").hasAnyAuthority("DELETE:USER")
	            .requestMatchers(HttpMethod.DELETE, "/customer/delete/**").hasAnyAuthority("DELETE:CUSTOMER")
	            .anyRequest().authenticated()
	        )
	        .addFilterBefore(customAuthorizationFilter, UsernamePasswordAuthenticationFilter.class)
	        .exceptionHandling(exception -> exception
	            .accessDeniedHandler(customAccessDeniedHandler)
	            .authenticationEntryPoint(customAuthenticationEntryPoint)
	        );

	    return http.build();
	}

	@Bean
	CorsConfigurationSource corsConfigurationSource() {
	    CorsConfiguration configuration = new CorsConfiguration();
	    configuration.setAllowedOrigins(List.of("http://localhost:4200")); 
	    configuration.setAllowedMethods(ALLOWED_METHODS);
	    configuration.setAllowedHeaders(List.of("*"));
	    configuration.setExposedHeaders(List.of("*"));
	    configuration.setAllowCredentials(true);
	    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
	    source.registerCorsConfiguration("/**", configuration);
	    return source;
	}
}
