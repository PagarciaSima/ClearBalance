package com.clear.balance.clearBalance.filter;


import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.clear.balance.clearBalance.provider.TokenProvider;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * @author Junior RT
 * @version 1.0
 * @license Get Arrays, LLC (https://getarrays.io)
 * @since 1/2/2023
 */

@Component
@RequiredArgsConstructor
@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {

	private static final String HTTP_OPTIONS_METHOD = "OPTIONS";
	private static final String TOKEN_PREFIX = "Bearer ";
	private final TokenProvider tokenProvider;
	private static final String TOKEN_KEY = "token";
	protected static final String EMAIL_KEY = "email";
	private static final String [] PUBLIC_ROUTES = {
			"/user/login",
			"user/verify/code",
			"/user/register"
	};
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		try {
			Map<String, String> values = getRequestValues(request);
			String token = this.getToken(request);
			if(this.tokenProvider.isTokenValid(values.get("email"), token)) {
				List<GrantedAuthority> authorities = this.tokenProvider.getAuthoritiesFromToken(values.get(TOKEN_KEY));
				Authentication authentication = this.tokenProvider.getAuthentication(values.get(EMAIL_KEY), authorities, request);
				SecurityContextHolder.getContext().setAuthentication(authentication);
			} else {
				SecurityContextHolder.clearContext();
			}
			filterChain.doFilter(request, response);
		} catch (Exception e) {
			log.error("Error logging in: {}", e.getMessage());
			processError(request, response, e);
		}
	}
	
	private void processError(HttpServletRequest request, HttpServletResponse response, Exception e) {
		// TODO Auto-generated method stub
		
	}

	/**
	 * Extracts the JWT token from the HTTP Authorization header if present and properly formatted.
	 * <p>
	 * This method retrieves the value of the {@code Authorization} header from the given HTTP request.
	 * If the header exists and starts with the prefix defined by {@link #TOKEN_PREFIX} (typically {@code "Bearer "}),
	 * it removes the prefix, trims any extra whitespace, and returns the resulting token string.
	 * If the header is missing or does not start with the expected prefix, this method returns {@code null}.
	 * </p>
	 *
	 * @param request the {@link HttpServletRequest} containing the Authorization header
	 * @return the extracted token without the prefix, or {@code null} if no valid token is found
	 */
	private String getToken(HttpServletRequest request) {
	    return Optional.ofNullable(request.getHeader(HttpHeaders.AUTHORIZATION))
	            .filter(header -> header.startsWith(TOKEN_PREFIX))
	            // Replace prefix "Bearer " and trim whitespace
	            .map(header -> header.replace(TOKEN_PREFIX, "").trim())
	            .orElse(null);
	}

	/**
	 * Determines whether this filter should be skipped for the current HTTP request.
	 * <p>
	 * This method checks several conditions to decide if the authorization filter
	 * should not be applied. It skips filtering when:
	 * <ul>
	 *   <li>No {@code Authorization} header is present in the request.</li>
	 *   <li>The {@code Authorization} header does not start with the expected token prefix (e.g., {@code "Bearer "}).</li>
	 *   <li>The HTTP method is {@code OPTIONS}, which is typically used for CORS preflight requests.</li>
	 *   <li>The requested URI matches any public route that does not require authentication.</li>
	 * </ul>
	 * If none of these conditions apply, the filter will proceed with normal authentication processing.
	 *
	 * @param request the {@link HttpServletRequest} to inspect
	 * @return {@code true} if the filter should be skipped for this request; {@code false} otherwise
	 * @throws ServletException if an error occurs while evaluating the request
	 */
	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
	    if (request.getHeader(HttpHeaders.AUTHORIZATION) == null) {
	        return true;
	    }

	    if (!request.getHeader(HttpHeaders.AUTHORIZATION).startsWith(TOKEN_PREFIX)) {
	        return true;
	    }

	    // Skip filtering for HTTP OPTIONS requests (used in CORS preflight checks)
	    if (request.getMethod().equalsIgnoreCase(HTTP_OPTIONS_METHOD)) {
	        return true;
	    }

	    if (Arrays.asList(PUBLIC_ROUTES).contains(request.getRequestURI())) {
	        return true;
	    }

	    return false;
	}
	
	Map<String, String> getRequestValues(HttpServletRequest request) {
        return Map.of(
    		EMAIL_KEY, tokenProvider.getSubject(getToken(request), request),
    		TOKEN_KEY, getToken(request)
		);
    }
}