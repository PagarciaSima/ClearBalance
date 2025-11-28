package com.clear.balance.clearBalance.provider;

import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.clear.balance.clearBalance.domain.UserPrincipal;
import com.clear.balance.clearBalance.service.UserService;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Provides functionality for generating JSON Web Tokens (JWT) including both
 * access and refresh tokens for authenticated users.
 * <p>
 * Uses HMAC512 algorithm and secret key defined in application configuration.
 * </p>
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class TokenProvider {

	private static final String CLEAR_BALANCE_LLC = "CLEAR_BALANCE_LLC";
	public static final String CUSTOMER_MANAGEMENT_SERVICE = "CUSTOMER_MANAGEMENT_SERVICE";
	public static final String AUTHORITIES = "authorities";
	public static final long ACCESS_TOKEN_EXPIRATION_TIME = 24 * 60 * 60 * 1000; // 30 seconds
	private static final long REFRESH_TOKEN_EXPIRATION_TIME = 24 * 60 * 60 * 1000 * 3; // 3 days
	private static final String TOKEN_CANNOT_BE_VERIFIED = "Token cannot be verified";
	private final UserService userService;

	@Value("${jwt.secret}")
	private String secret;

	/**
	 * Generates a signed JWT access token containing user authorities (during login or mfa auth).
	 *
	 * @param userPrincipal The authenticated user's principal
	 * @return A signed JWT access token string
	 */
	public String createAccessToken(UserPrincipal userPrincipal) {
		log.info("Creating access token for user: {}", userPrincipal.getUsername());
		try {
			String[] roles = getRolesFromUser(userPrincipal);
			String token = JWT.create().withIssuer(CLEAR_BALANCE_LLC).withAudience(CUSTOMER_MANAGEMENT_SERVICE)
					.withIssuedAt(new Date())
					.withSubject(String.valueOf(userPrincipal.getUser().getId()))
					.withArrayClaim(AUTHORITIES, roles)
					.withExpiresAt(new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRATION_TIME))
					.sign(Algorithm.HMAC512(secret.getBytes()));
			log.debug("Access token successfully created for user: {}", userPrincipal.getUsername());
			return token;
		} catch (Exception e) {
			log.error("Error while creating access token for user: {}", userPrincipal.getUsername(), e);
			throw e;
		}
	}

	/**
	 * Generates a signed JWT refresh token without user authorities. Used to
	 * request a new access token once the previous one expires.
	 *
	 * @param userPrincipal The authenticated user's principal
	 * @return A signed JWT refresh token string
	 */
	public String createRefreshToken(UserPrincipal userPrincipal) {
		log.info("Creating refresh token for user: {}", userPrincipal.getUsername());
		try {
			String token = JWT.create().withIssuer(CLEAR_BALANCE_LLC).withAudience(CUSTOMER_MANAGEMENT_SERVICE)
					.withIssuedAt(new Date())
					.withSubject(String.valueOf(userPrincipal.getUser().getId()))
					.withExpiresAt(new Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRATION_TIME))
					.sign(Algorithm.HMAC512(secret.getBytes()));
			log.debug("Refresh token successfully created for user: {}", userPrincipal.getUsername());
			return token;
		} catch (Exception e) {
			log.error("Error while creating refresh token for user: {}", userPrincipal.getUsername(), e);
			throw e;
		}
	}
	
	/**
	 * Extracts and returns the subject from a JWT token.
	 * <p>
	 * This method verifies the provided JWT token using the configured verifier and
	 * retrieves the token's subject, which in this implementation represents the
	 * user's unique identifier (ID). The subject is then converted from a string
	 * to a {@link Long} before being returned.
	 * </p>
	 *
	 * <p>
	 * If the token is expired, contains invalid claims, or fails verification for any
	 * other reason, the appropriate exception is logged and rethrown.
	 * </p>
	 *
	 * @param token   the JWT token from which the subject should be extracted
	 * @param request the current HTTP request (included for consistency and potential future use)
	 * @return the subject of the token as a {@link Long} representing the user ID
	 *
	 * @throws com.auth0.jwt.exceptions.TokenExpiredException if the token has expired
	 * @throws com.auth0.jwt.exceptions.InvalidClaimException if the token contains invalid or unexpected claims
	 * @throws RuntimeException if any other error occurs during token verification
	 */
	public Long getSubject(String token, HttpServletRequest request) {
	    log.debug("Attempting to extract subject from token.");
	    try {
	        DecodedJWT decodedJWT = this.getJWTVerifier().verify(token);
	        String subject = decodedJWT.getSubject();
	        log.info("Successfully retrieved subject '{}' from token.", subject);
	        return Long.valueOf(subject);

	    } catch (TokenExpiredException e) {
	        log.error("Token has expired: {}", e.getMessage());
	        throw e; 
	    } catch (InvalidClaimException e) {
	        log.error("Invalid claim in token: {}", e.getMessage());
	        throw e;

	    } catch (Exception e) {
	        log.error("Error verifying token: {}", e.getMessage(), e);
	        throw new RuntimeException(e);
	    }
	}
    
	/**
	 * Extracts granted authorities (roles/permissions) from a verified JWT token.
	 *
	 * @param token the JWT token to decode and verify
	 * @return a list of {@link GrantedAuthority} objects extracted from the token
	 *         claims
	 * @throws JWTVerificationException if the token is invalid or cannot be
	 *                                  verified
	 */
	public List<GrantedAuthority> getAuthoritiesFromToken(String token) {
		log.debug("Attempting to extract authorities from token...");
		String[] claims = getClaimsFromToken(token);
		log.debug("Claims successfully extracted: {}", (Object) claims);
		List<GrantedAuthority> authorities = Arrays.stream(claims).map(SimpleGrantedAuthority::new)
				.collect(Collectors.toList());
		log.info("Extracted {} authorities from token", authorities.size());
		return authorities;
	}
	
	/**
	 * Builds a Spring Security {@link Authentication} token for a given user ID and authorities.
	 * <p>
	 * This method fetches the user by ID, creates a {@link UsernamePasswordAuthenticationToken},
	 * and attaches extra request details like IP address and session ID.
	 *
	 * @param userId      The ID of the user to authenticate.
	 * @param authorities List of {@link GrantedAuthority} granted to the user.
	 * @param request     The {@link HttpServletRequest} containing request-specific information.
	 * @return An {@link Authentication} token ready to be used in the Spring Security context.
	 */
	public Authentication getAuthentication(Long userId, List<GrantedAuthority> authorities,
	                                        HttpServletRequest request) {

	    log.debug("Building authentication token for userId: {}", userId);

	    // Fetch the user entity by ID
	    var user = userService.getUserById(userId);

	    UsernamePasswordAuthenticationToken userPasswordAuthToken =
	            new UsernamePasswordAuthenticationToken(user, null, authorities);

	    // Set extra data like IP address, session ID, etc.
	    userPasswordAuthToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

	    log.info("Authentication token successfully created for userId: {} with {} authorities",
	            userId, authorities.size());

	    return userPasswordAuthToken;
	}
	
    /**
     * Validates if a JWT token is valid for a given user ID.
     * <p>
     * This method checks if the provided token is non-null, properly signed,
     * and not expired for the specified user.
     *
     * @param userId the ID of the user to validate the token against
     * @param token the JWT token to validate
     * @return {@code true} if the token is valid for the given user ID and not expired, {@code false} otherwise
     */
    public boolean isTokenValid(Long userId, String token) {
        log.debug("Validating token for userId: {}", userId);

        if (userId == null) {
            log.warn("User ID is null. Token is invalid.");
            return false;
        }

        if (token == null || token.isBlank()) {
            log.warn("Token is null or empty. Token is invalid for userId: {}", userId);
            return false;
        }

        JWTVerifier verifier = getJWTVerifier();

        if (isTokenExpired(verifier, token)) {
            log.warn("Token for userId {} has expired.", userId);
            return false;
        }

        log.info("Token for userId {} is valid.", userId);
        return true;
    }

    /**
     * Checks if a JWT token has expired.
     *
     * @param verifier the JWT verifier
     * @param token the token to check
     * @return true if the token has expired, false if it is still valid
     */
    private boolean isTokenExpired(JWTVerifier verifier, String token) {
        Date expiration = verifier.verify(token).getExpiresAt();
        boolean expired = expiration.before(new Date());

        if (expired) {
            log.debug("Token expired at: {}", expiration);
        } else {
            log.debug("Token is still valid. Expires at: {}", expiration);
        }

        return expired;
    }

	/**
	 * Retrieves the 'authorities' claim array from a JWT after verifying its
	 * signature and issuer.
	 *
	 * @param token the JWT token to decode
	 * @return an array of claim values representing authorities
	 * @throws JWTVerificationException if verification fails
	 */
	private String[] getClaimsFromToken(String token) {
		log.debug("Verifying token and extracting authority claims...");
		JWTVerifier verifier = getJWTVerifier();
		String[] claims = verifier.verify(token).getClaim(AUTHORITIES).asArray(String.class);
		log.debug("Token verified successfully. {} authorities found.", claims != null ? claims.length : 0);
		return claims;
	}

	/**
	 * Creates and configures a {@link JWTVerifier} using the application's secret
	 * and expected issuer. This verifier automatically checks the token signature,
	 * issuer, expiration, and other constraints.
	 *
	 * @return a configured {@link JWTVerifier} instance
	 * @throws JWTVerificationException if the verifier cannot be initialized
	 *                                  properly
	 */
	private JWTVerifier getJWTVerifier() {
		try {
			log.debug("Initializing JWT verifier with issuer: {}", CLEAR_BALANCE_LLC);
			Algorithm algorithm = Algorithm.HMAC512(secret);
			JWTVerifier verifier = JWT.require(algorithm).withIssuer(CLEAR_BALANCE_LLC).build();
			log.info("JWT verifier successfully initialized");
			return verifier;
		} catch (JWTVerificationException exception) {
			log.error("Failed to initialize JWT verifier: {}", exception.getMessage());
			throw new JWTVerificationException(TOKEN_CANNOT_BE_VERIFIED);
		}
	}

	/**
	 * Extracts granted authorities from the user principal and returns them as an
	 * array of strings.
	 *
	 * @param userPrincipal The authenticated user's principal
	 * @return Array of role or permission names
	 */
	private String[] getRolesFromUser(UserPrincipal userPrincipal) {
		log.trace("Extracting roles from user: {}", userPrincipal.getUsername());
		String[] roles = userPrincipal.getAuthorities().stream().map(GrantedAuthority::getAuthority)
				.toArray(String[]::new);
		log.trace("Extracted {} roles for user: {}", roles.length, userPrincipal.getUsername());
		return roles;
	}
}
