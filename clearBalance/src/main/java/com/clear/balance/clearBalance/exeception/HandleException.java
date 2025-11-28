package com.clear.balance.clearBalance.exeception;

import java.sql.SQLIntegrityConstraintViolationException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.clear.balance.clearBalance.domain.HttpResponse;

import lombok.extern.slf4j.Slf4j;

@ControllerAdvice
@Slf4j
public class HandleException extends ResponseEntityExceptionHandler implements ErrorController {

	/**
	 * Handles internal exceptions thrown during request processing by building a standardized {@link HttpResponse}.
	 * <p>
	 * This method overrides Spring's default {@link ResponseEntityExceptionHandler#handleExceptionInternal}
	 * to provide a consistent JSON response structure for all handled exceptions.
	 * <p>
	 * The response includes a timestamp, HTTP status information, and both a user-facing reason and a developer message.
	 * <p>
	 * Logging:
	 * <ul>
	 *   <li>Logs the exception type and message at the error level.</li>
	 *   <li>Logs the HTTP status code being returned.</li>
	 * </ul>
	 *
	 * @param ex the exception that was thrown
	 * @param body the body to be written to the response (usually null)
	 * @param headers the HTTP headers to include in the response
	 * @param statusCode the HTTP status code associated with the exception
	 * @param request the current web request context
	 * @return a {@link ResponseEntity} containing a standardized {@link HttpResponse} body
	 */
	@Override
	protected ResponseEntity<Object> handleExceptionInternal(
	        Exception ex,
	        Object body,
	        HttpHeaders headers,
	        HttpStatusCode statusCode,
	        WebRequest request) {

	    log.error("Handling exception of type [{}]: {}", ex.getClass().getSimpleName(), ex.getMessage());
	    log.debug("Exception details:", ex);
	    log.info("Returning HTTP status: {}", statusCode.value());

	    HttpResponse httpResponse = HttpResponse.builder()
	            .timeStamp(LocalDateTime.now().toString())
	            .reason(ex.getMessage())
	            .developerMessage(ex.getMessage())
	            .status(HttpStatus.resolve(statusCode.value()))
	            .statusCode(statusCode.value())
	            .build();

	    return new ResponseEntity<>(httpResponse, headers, statusCode);
	}

	/**
	 * Handles validation errors that occur when a method argument annotated with {@code @Valid}
	 * fails validation constraints.
	 * <p>
	 * This method overrides Spring's {@link ResponseEntityExceptionHandler#handleMethodArgumentNotValid}
	 * to provide a consistent JSON response structure for validation errors.
	 * <p>
	 * The response includes:
	 * <ul>
	 *   <li>A timestamp of when the error occurred.</li>
	 *   <li>A concatenated list of all field validation messages as the {@code reason}.</li>
	 *   <li>The original exception message as the {@code developerMessage}.</li>
	 *   <li>The corresponding HTTP status and code.</li>
	 * </ul>
	 * <p>
	 * Logging:
	 * <ul>
	 *   <li>Logs the total number of invalid fields and their messages.</li>
	 *   <li>Logs the HTTP status code being returned.</li>
	 * </ul>
	 *
	 * @param ex the {@link MethodArgumentNotValidException} containing validation errors
	 * @param headers the HTTP headers to include in the response
	 * @param statusCode the HTTP status code associated with the validation error
	 * @param request the current web request context
	 * @return a {@link ResponseEntity} containing a standardized {@link HttpResponse} body
	 */
	@Override
	protected ResponseEntity<Object> handleMethodArgumentNotValid(
	        MethodArgumentNotValidException ex,
	        HttpHeaders headers,
	        HttpStatusCode statusCode,
	        WebRequest request) {

	    List<FieldError> fieldErrors = ex.getBindingResult().getFieldErrors();
	    String fieldMessage = fieldErrors.stream()
	            .map(FieldError::getDefaultMessage)
	            .collect(Collectors.joining(", "));

	    log.error("Validation failed for {} field(s): {}", fieldErrors.size(), fieldMessage);
	    log.debug("Validation exception details:", ex);
	    log.info("Returning HTTP status: {}", statusCode.value());

	    HttpResponse httpResponse = HttpResponse.builder()
	            .timeStamp(LocalDateTime.now().toString())
	            .reason(fieldMessage)
	            .developerMessage(ex.getMessage())
	            .status(HttpStatus.resolve(statusCode.value()))
	            .statusCode(statusCode.value())
	            .build();

	    return new ResponseEntity<>(httpResponse, headers, statusCode);
	}
	
	/**
	 * Handles {@link SQLIntegrityConstraintViolationException} thrown by the database layer,
	 * typically when a unique constraint or foreign key constraint is violated.
	 * <p>
	 * This method intercepts database integrity violations (for example, duplicate entries)
	 * and returns a standardized {@link HttpResponse} with relevant error details.
	 * <p>
	 * Behavior:
	 * <ul>
	 *   <li>If the exception message contains "Duplicate entry", a user-friendly message is returned.</li>
	 *   <li>Otherwise, the original exception message is used as the reason.</li>
	 * </ul>
	 * <p>
	 * Logging:
	 * <ul>
	 *   <li>Logs the detected constraint violation and its SQL message at the error level.</li>
	 *   <li>Logs the generated HTTP status being returned.</li>
	 * </ul>
	 *
	 * @param ex the {@link SQLIntegrityConstraintViolationException} thrown due to a database constraint violation
	 * @return a {@link ResponseEntity} containing a standardized {@link HttpResponse} with a BAD_REQUEST status
	 */
	@ExceptionHandler(SQLIntegrityConstraintViolationException.class)
	public ResponseEntity<HttpResponse> sQLIntegrityConstraintViolationException(SQLIntegrityConstraintViolationException ex) {

	    String message = ex.getMessage().contains("Duplicate entry")
	            ? "Duplicate entry found."
	            : ex.getMessage();

	    log.error("Database integrity constraint violation detected: {}", message);
	    log.debug("SQL exception details:", ex);
	    log.info("Returning HTTP status: {}", HttpStatus.BAD_REQUEST.value());

	    HttpResponse httpResponse = HttpResponse.builder()
	            .timeStamp(LocalDateTime.now().toString())
	            .reason(message)
	            .developerMessage(ex.getMessage())
	            .status(HttpStatus.BAD_REQUEST)
	            .statusCode(HttpStatus.BAD_REQUEST.value())
	            .build();

	    return new ResponseEntity<>(httpResponse, HttpStatus.BAD_REQUEST);
	}
	
	/**
	 * Handles {@link org.springframework.security.authentication.BadCredentialsException}
	 * thrown when authentication fails due to invalid username or password credentials.
	 * <p>
	 * This method captures authentication errors and returns a standardized {@link HttpResponse}
	 * object with a {@code 401 UNAUTHORIZED} status code.
	 * <p>
	 * Behavior:
	 * <ul>
	 *   <li>Provides a user-friendly message indicating invalid credentials.</li>
	 *   <li>Logs the authentication failure details for debugging and audit purposes.</li>
	 * </ul>
	 * <p>
	 * Logging:
	 * <ul>
	 *   <li>Logs the authentication failure message at the error level.</li>
	 *   <li>Logs exception details at the debug level for developers.</li>
	 *   <li>Logs the HTTP status being returned.</li>
	 * </ul>
	 *
	 * @param ex the {@link org.springframework.security.authentication.BadCredentialsException}
	 *           thrown when authentication fails
	 * @return a {@link ResponseEntity} containing a standardized {@link HttpResponse}
	 *         with a {@code 401 UNAUTHORIZED} status
	 */
	@ExceptionHandler(BadCredentialsException.class)
	public ResponseEntity<HttpResponse> handleBadCredentialsException(BadCredentialsException ex) {

	    String message = "Invalid username or password. Please check your credentials and try again.";

	    log.error("Authentication failed: {}", message);
	    log.debug("BadCredentialsException details:", ex);
	    log.info("Returning HTTP status: {}", HttpStatus.UNAUTHORIZED.value());

	    HttpResponse httpResponse = HttpResponse.builder()
	            .timeStamp(LocalDateTime.now().toString())
	            .reason(message)
	            .developerMessage(ex.getMessage())
	            .status(HttpStatus.UNAUTHORIZED)
	            .statusCode(HttpStatus.UNAUTHORIZED.value())
	            .build();

	    return new ResponseEntity<>(httpResponse, HttpStatus.UNAUTHORIZED);
	}
	
	  /**
     * Handles {@link JWTDecodeException} thrown when a JWT token is malformed, empty, or invalid.
     * <p>
     * This typically occurs when:
     * <ul>
     *   <li>Token is empty or null</li>
     *   <li>Token doesn't have the expected 3 parts (header.payload.signature)</li>
     *   <li>Token contains invalid Base64 encoding</li>
     *   <li>Token JSON structure is malformed</li>
     * </ul>
     *
     * @param ex the {@link JWTDecodeException} thrown during JWT processing
     * @return a {@link ResponseEntity} containing a standardized {@link HttpResponse} with 401 UNAUTHORIZED status
     */
    @ExceptionHandler(JWTDecodeException.class)
    public ResponseEntity<HttpResponse> handleJWTDecodeException(JWTDecodeException ex) {
        
        String message = "Invalid authentication token format.";
        
        log.error("JWT decode error: {}", ex.getMessage());
        log.debug("JWTDecodeException details:", ex);
        log.info("Returning HTTP status: {}", HttpStatus.UNAUTHORIZED.value());

        HttpResponse httpResponse = HttpResponse.builder()
                .timeStamp(LocalDateTime.now().toString())
                .reason(message)
                .developerMessage("Token decoding failed: " + ex.getMessage())
                .status(HttpStatus.UNAUTHORIZED)
                .statusCode(HttpStatus.UNAUTHORIZED.value())
                .build();

        return new ResponseEntity<>(httpResponse, HttpStatus.UNAUTHORIZED);
    }

    /**
     * Handles {@link TokenExpiredException} thrown when a JWT token has expired.
     * <p>
     * This occurs when the token's expiration time (exp claim) is in the past.
     *
     * @param ex the {@link TokenExpiredException} thrown during JWT validation
     * @return a {@link ResponseEntity} containing a standardized {@link HttpResponse} with 401 UNAUTHORIZED status
     */
    @ExceptionHandler(TokenExpiredException.class)
    public ResponseEntity<HttpResponse> handleTokenExpiredException(TokenExpiredException ex) {
        
        String message = "Your session has expired. Please log in again.";
        
        log.warn("Token expired: {}", ex.getMessage());
        log.debug("TokenExpiredException details:", ex);

        HttpResponse httpResponse = HttpResponse.builder()
                .timeStamp(LocalDateTime.now().toString())
                .reason(message)
                .developerMessage("Token expired at: " + ex.getExpiredOn())
                .status(HttpStatus.UNAUTHORIZED)
                .statusCode(HttpStatus.UNAUTHORIZED.value())
                .build();

        return new ResponseEntity<>(httpResponse, HttpStatus.UNAUTHORIZED);
    }


	/**
	 * Handles custom {@link com.clear.balance.clearBalance.exeception.ApiException}
	 * thrown within the application to represent controlled business or validation errors.
	 * <p>
	 * This method returns a standardized {@link HttpResponse} with a {@code 400 BAD_REQUEST} status,
	 * providing both a user-facing reason and a developer message for debugging purposes.
	 * <p>
	 * Behavior:
	 * <ul>
	 *   <li>Extracts the custom message from the {@link ApiException}.</li>
	 *   <li>Logs the exception type and message at the error level.</li>
	 *   <li>Logs technical details at the debug level for developers.</li>
	 * </ul>
	 * <p>
	 * Logging:
	 * <ul>
	 *   <li>Logs a concise error summary for end-user context.</li>
	 *   <li>Logs the full stack trace in debug mode.</li>
	 *   <li>Logs the HTTP status being returned.</li>
	 * </ul>
	 *
	 * @param ex the {@link com.clear.balance.clearBalance.exeception.ApiException}
	 *           representing a business logic or API-level validation error
	 * @return a {@link ResponseEntity} containing a standardized {@link HttpResponse}
	 *         with a {@code 400 BAD_REQUEST} status
	 */
	@ExceptionHandler(ApiException.class)
	public ResponseEntity<HttpResponse> handleApiException(ApiException ex) {

	    String message = ex.getMessage() != null ? ex.getMessage() : "A bad request occurred.";

	    log.error("API exception encountered: {}", message);
	    log.debug("ApiException details:", ex);
	    log.info("Returning HTTP status: {}", HttpStatus.BAD_REQUEST.value());

	    HttpResponse httpResponse = HttpResponse.builder()
	            .timeStamp(LocalDateTime.now().toString())
	            .reason(message)
	            .developerMessage(ex.getMessage())
	            .status(HttpStatus.BAD_REQUEST)
	            .statusCode(HttpStatus.BAD_REQUEST.value())
	            .build();

	    return new ResponseEntity<>(httpResponse, HttpStatus.BAD_REQUEST);
	}

	/**
	 * Handles {@link org.springframework.security.access.AccessDeniedException}
	 * thrown when an authenticated user attempts to access a resource
	 * for which they do not have sufficient permissions.
	 * <p>
	 * This method returns a standardized {@link HttpResponse} with a
	 * {@code 403 FORBIDDEN} status code, indicating that the request was understood
	 * but refused due to lack of authorization.
	 * <p>
	 * Behavior:
	 * <ul>
	 *   <li>Provides a clear and user-friendly message indicating lack of access rights.</li>
	 *   <li>Logs the exception details for auditing and debugging purposes.</li>
	 * </ul>
	 * <p>
	 * Logging:
	 * <ul>
	 *   <li>Logs the access denial reason at the error level.</li>
	 *   <li>Logs the exception stack trace at the debug level.</li>
	 *   <li>Logs the HTTP status being returned.</li>
	 * </ul>
	 *
	 * @param ex the {@link org.springframework.security.access.AccessDeniedException}
	 *           thrown when a user is not authorized to access a specific resource
	 * @return a {@link ResponseEntity} containing a standardized {@link HttpResponse}
	 *         with a {@code 403 FORBIDDEN} status
	 */
	@ExceptionHandler(AccessDeniedException.class)
	public ResponseEntity<HttpResponse> handleAccessDeniedException(AccessDeniedException ex) {

	    String message = "Access denied. You do not have permission to perform this action.";

	    log.error("Access denied: {}", message);
	    log.debug("AccessDeniedException details:", ex);
	    log.info("Returning HTTP status: {}", HttpStatus.FORBIDDEN.value());

	    HttpResponse httpResponse = HttpResponse.builder()
	            .timeStamp(LocalDateTime.now().toString())
	            .reason(message)
	            .developerMessage(ex.getMessage())
	            .status(HttpStatus.FORBIDDEN)
	            .statusCode(HttpStatus.FORBIDDEN.value())
	            .build();

	    return new ResponseEntity<>(httpResponse, HttpStatus.FORBIDDEN);
	}
	
	/**
	 * Handles any uncaught or unexpected {@link Exception} in the application.
	 * <p>
	 * This method acts as a global fallback for all exceptions not explicitly
	 * handled by other {@code @ExceptionHandler} methods. It returns a standardized
	 * {@link HttpResponse} with a {@code 500 INTERNAL_SERVER_ERROR} status code.
	 * <p>
	 * Behavior:
	 * <ul>
	 *   <li>Provides a generic error message to the user while avoiding leaking sensitive information.</li>
	 *   <li>Logs full exception details for debugging purposes.</li>
	 * </ul>
	 * <p>
	 * Logging:
	 * <ul>
	 *   <li>Logs a high-level error message at the error level.</li>
	 *   <li>Logs the full stack trace at the debug level.</li>
	 *   <li>Logs the HTTP status being returned.</li>
	 * </ul>
	 *
	 * @param ex the uncaught {@link Exception} that occurred
	 * @return a {@link ResponseEntity} containing a standardized {@link HttpResponse}
	 *         with a {@code 500 INTERNAL_SERVER_ERROR} status
	 */
	@ExceptionHandler(Exception.class)
	public ResponseEntity<HttpResponse> handleGenericException(Exception ex) {

	    String message = "An unexpected error occurred. Please try again later.";

	    log.error("Unexpected exception: {}", message);
	    log.debug("Exception details:", ex);
	    log.info("Returning HTTP status: {}", HttpStatus.INTERNAL_SERVER_ERROR.value());

	    HttpResponse httpResponse = HttpResponse.builder()
	            .timeStamp(LocalDateTime.now().toString())
	            .reason(message)
	            .developerMessage(ex.getMessage())
	            .status(HttpStatus.INTERNAL_SERVER_ERROR)
	            .statusCode(HttpStatus.INTERNAL_SERVER_ERROR.value())
	            .build();

	    return new ResponseEntity<>(httpResponse, HttpStatus.INTERNAL_SERVER_ERROR);
	}

	/**
	 * Handles {@link org.springframework.security.authentication.DisabledException}
	 * thrown when a user account is disabled and cannot authenticate.
	 * <p>
	 * Returns a standardized {@link HttpResponse} with a {@code 400 BAD_REQUEST} status,
	 * providing both a user-friendly reason and a developer message.
	 *
	 * Logging:
	 * <ul>
	 *   <li>Error level: concise message for the user.</li>
	 *   <li>Debug level: full stack trace.</li>
	 *   <li>Info level: HTTP status returned.</li>
	 * </ul>
	 *
	 * @param ex the {@link DisabledException} thrown during authentication
	 * @return a {@link ResponseEntity} containing a standardized {@link HttpResponse}
	 *         with {@code 400 BAD_REQUEST}
	 */
	@ExceptionHandler(DisabledException.class)
	public ResponseEntity<HttpResponse> handleDisabledException(DisabledException ex) {

	    String message = "User account is disabled.";

	    log.error("Authentication failed: {}", message);
	    log.debug("DisabledException details:", ex);
	    log.info("Returning HTTP status: {}", HttpStatus.BAD_REQUEST.value());

	    HttpResponse httpResponse = HttpResponse.builder()
	            .timeStamp(LocalDateTime.now().toString())
	            .reason(message)
	            .developerMessage(ex.getMessage())
	            .status(HttpStatus.BAD_REQUEST)
	            .statusCode(HttpStatus.BAD_REQUEST.value())
	            .build();

	    return new ResponseEntity<>(httpResponse, HttpStatus.BAD_REQUEST);
	}

	/**
	 * Handles {@link org.springframework.security.authentication.LockedException}
	 * thrown when a user account is locked and cannot authenticate.
	 * <p>
	 * Returns a standardized {@link HttpResponse} with a {@code 400 BAD_REQUEST} status,
	 * providing both a user-friendly reason and a developer message.
	 *
	 * Logging:
	 * <ul>
	 *   <li>Error level: concise message for the user.</li>
	 *   <li>Debug level: full stack trace.</li>
	 *   <li>Info level: HTTP status returned.</li>
	 * </ul>
	 *
	 * @param ex the {@link LockedException} thrown during authentication
	 * @return a {@link ResponseEntity} containing a standardized {@link HttpResponse}
	 *         with {@code 400 BAD_REQUEST}
	 */
	@ExceptionHandler(LockedException.class)
	public ResponseEntity<HttpResponse> handleLockedException(LockedException ex) {

	    String message = "User account is locked.";

	    log.error("Authentication failed: {}", message);
	    log.debug("LockedException details:", ex);
	    log.info("Returning HTTP status: {}", HttpStatus.BAD_REQUEST.value());

	    HttpResponse httpResponse = HttpResponse.builder()
	            .timeStamp(LocalDateTime.now().toString())
	            .reason(message)
	            .developerMessage(ex.getMessage())
	            .status(HttpStatus.BAD_REQUEST)
	            .statusCode(HttpStatus.BAD_REQUEST.value())
	            .build();

	    return new ResponseEntity<>(httpResponse, HttpStatus.BAD_REQUEST);
	}
	
	/**
	 * Handles {@link org.springframework.dao.DataAccessException} and its subclasses.
	 * <p>
	 * This exception occurs when there is a database access problem, such as
	 * constraint violations, empty results when a single result is expected,
	 * or other data access errors.
	 * <p>
	 * Returns a standardized {@link HttpResponse} with {@code 400 BAD_REQUEST} status,
	 * providing a user-friendly reason and developer message.
	 *
	 * Logging:
	 * <ul>
	 *   <li>Error level: concise message for the user.</li>
	 *   <li>Debug level: full exception stack trace.</li>
	 *   <li>Info level: HTTP status returned.</li>
	 * </ul>
	 *
	 * @param ex the {@link DataAccessException} thrown during database operations
	 * @return a {@link ResponseEntity} containing a standardized {@link HttpResponse}
	 *         with {@code 400 BAD_REQUEST}
	 */
	@ExceptionHandler(DataAccessException.class)
	public ResponseEntity<HttpResponse> handleDataAccessException(DataAccessException ex) {

	    String message = "A database error occurred.";

	    // Customize message for some common cases
	    if (ex instanceof EmptyResultDataAccessException) {
	        message = "No data found for the requested resource.";
	    }

	    log.error("Data access error: {}", message);
	    log.debug("DataAccessException details:", ex);
	    log.info("Returning HTTP status: {}", HttpStatus.BAD_REQUEST.value());

	    HttpResponse httpResponse = HttpResponse.builder()
	            .timeStamp(LocalDateTime.now().toString())
	            .reason(message)
	            .developerMessage(ex.getMessage())
	            .status(HttpStatus.BAD_REQUEST)
	            .statusCode(HttpStatus.BAD_REQUEST.value())
	            .build();

	    return new ResponseEntity<>(httpResponse, HttpStatus.BAD_REQUEST);
	}

}
