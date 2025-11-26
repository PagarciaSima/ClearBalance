package com.clear.balance.clearBalance.filter;


import java.io.IOException;
import java.util.Arrays;
import java.util.List;
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
	protected static final String EMAIL_KEY = "email";
	private static final String [] PUBLIC_ROUTES = {
			"/user/login",
			"/user/verify/code",
			"/user/register",
			"/user/refresh/token",
			
	};
	
	/**
	 * Filters each HTTP request to authenticate the user via a token.
	 * <p>
	 * If the token is valid, sets authentication in the security context;
	 * otherwise, clears the context and logs a warning. Errors are handled
	 * via {@link ExceptionUtils#processError}.
	 * </p>
	 *
	 * @param request  the incoming HTTP request
	 * @param response the HTTP response
	 * @param filterChain the filter chain to continue
	 * @throws ServletException if a servlet error occurs
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
	        throws ServletException, IOException {

	    try {
	        String token = this.getToken(request);
	        Long userId = getUserId(request);

	        log.debug("Processing authentication for token: {}", token);

	        if (this.tokenProvider.isTokenValid(userId, token)) {
	            List<GrantedAuthority> authorities = this.tokenProvider.getAuthoritiesFromToken(token);
	            Authentication authentication = this.tokenProvider.getAuthentication(userId, authorities, request);
	            SecurityContextHolder.getContext().setAuthentication(authentication);
	            log.info("Authentication successful for user id: {}", userId);
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
	 * Extracts the user ID from the HTTP request token.
	 *
	 * @param request the incoming HTTP request
	 * @return the user ID associated with the token
	 */
	private Long getUserId(HttpServletRequest request) {
	    String token = this.getToken(request);
	    return this.tokenProvider.getSubject(token, request);
	}
}