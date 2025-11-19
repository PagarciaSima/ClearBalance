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

import com.clear.balance.clearBalance.Utils.ExceptionUtils;
import com.clear.balance.clearBalance.provider.TokenProvider;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

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
			"/user/verify/code",
			"/user/register",
			"/user/refresh/token",
			
	};
	
	/**
	 * Filters incoming HTTP requests to handle JWT-based authentication.
	 * <p>
	 * This method is invoked for every request (unless {@link #shouldNotFilter(HttpServletRequest)} returns true)
	 * and performs the following steps:
	 * <ol>
	 *     <li>Extracts the JWT token and subject (email) from the request using {@link #getRequestValues(HttpServletRequest)}.</li>
	 *     <li>Validates the token via {@link TokenProvider#isTokenValid(String, String)}.</li>
	 *     <li>If valid, retrieves authorities from the token and sets the {@link Authentication} object
	 *         in the {@link SecurityContextHolder}.</li>
	 *     <li>If invalid or null, clears the security context.</li>
	 *     <li>Delegates to the rest of the filter chain.</li>
	 * </ol>
	 * <p>
	 * Any exceptions during token processing (invalid signature, expired token, null values, etc.) are logged
	 * and processed using {@link ExceptionUtils#processError(HttpServletRequest, HttpServletResponse, Exception)}.
	 *
	 * @param request the incoming {@link HttpServletRequest}
	 * @param response the {@link HttpServletResponse} to write errors if needed
	 * @param filterChain the {@link FilterChain} to pass control to the next filter
	 * @throws ServletException if an exception occurs during filtering
	 * @throws IOException if an I/O error occurs during filtering
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
	        throws ServletException, IOException {

	    try {
	        Map<String, String> values = getRequestValues(request);
	        String token = this.getToken(request);

	        log.debug("Processing authentication for token: {}", token);

	        if (this.tokenProvider.isTokenValid(values.get(EMAIL_KEY), token)) {
	            List<GrantedAuthority> authorities = this.tokenProvider.getAuthoritiesFromToken(values.get(TOKEN_KEY));
	            Authentication authentication = this.tokenProvider.getAuthentication(values.get(EMAIL_KEY), authorities, request);
	            SecurityContextHolder.getContext().setAuthentication(authentication);

	            log.info("Authentication successful for email: {}", values.get(EMAIL_KEY));
	        } else {
	            SecurityContextHolder.clearContext();
	            log.warn("Invalid or missing token for request to {}", request.getRequestURI());
	        }

	        filterChain.doFilter(request, response);
	    } catch (Exception e) {
	        log.error("Error processing authentication: {}", e.getMessage(), e);
	        ExceptionUtils.processError(request, response, e);
	    }
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
	            .get();
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
	
	/**
	 * Extracts key values from the HTTP request related to authentication.
	 * <p>
	 * This method retrieves the JWT token from the request using {@link #getToken(HttpServletRequest)} 
	 * and then extracts the subject (typically the user's email) from the token via the {@link TokenProvider}.
	 * It returns a map containing:
	 * <ul>
	 *     <li>{@code "email"}: the subject extracted from the JWT token (may be null if the token is missing or invalid)</li>
	 *     <li>{@code "token"}: the raw JWT token extracted from the Authorization header (may be null if missing)</li>
	 * </ul>
	 * <p>
	 * Note: If the token is null or invalid, calling this method may result in a {@link NullPointerException} 
	 * when the subject cannot be retrieved. Consider adding null checks or exception handling when using this method.
	 *
	 * @param request the {@link HttpServletRequest} containing the Authorization header
	 * @return a {@link Map} with keys "email" and "token" containing the extracted values
	 */
	Map<String, String> getRequestValues(HttpServletRequest request) {
        return Map.of(
    		EMAIL_KEY, tokenProvider.getSubject(getToken(request), request),
    		TOKEN_KEY, getToken(request)
		);
    }
}