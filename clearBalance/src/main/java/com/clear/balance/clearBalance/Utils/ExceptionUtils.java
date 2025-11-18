package com.clear.balance.clearBalance.Utils;

import java.io.IOException;
import java.io.OutputStream;
import java.time.LocalDateTime;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;

import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.clear.balance.clearBalance.domain.HttpResponse;
import com.clear.balance.clearBalance.exeception.ApiException;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ExceptionUtils {

	private static final String GENERIC_ERROR_MSG = "An unexpected error ocurred. Please try again later.";

	/**
	 * Processes exceptions that occur during request handling and writes a JSON response to the client.
	 * <p>
	 * This method distinguishes between known authentication/authorization-related exceptions and generic exceptions:
	 * <ul>
	 *     <li>Known exceptions (e.g., {@link ApiException}, {@link DisabledException}, {@link LockedException}, 
	 *     {@link BadCredentialsException}, {@link InvalidClaimException}, {@link TokenExpiredException}) result in
	 *     a {@link HttpStatus#BAD_REQUEST} response with the exception's message.</li>
	 *     <li>All other exceptions result in a generic {@link HttpStatus#INTERNAL_SERVER_ERROR} response
	 *     with a standard error message.</li>
	 * </ul>
	 * <p>
	 * The response is written as JSON using {@link HttpResponse} and the {@link #writeResponse(HttpServletResponse, HttpResponse)}
	 * helper method.
	 *
	 * @param request the {@link HttpServletRequest} during which the exception occurred
	 * @param response the {@link HttpServletResponse} used to send the error response
	 * @param ex the {@link Exception} that occurred
	 */
	public static void processError(HttpServletRequest request, HttpServletResponse response, Exception ex) {
	    if (
	        ex instanceof ApiException || ex instanceof DisabledException
	        || ex instanceof LockedException || ex instanceof BadCredentialsException
	        || ex instanceof InvalidClaimException || ex instanceof TokenExpiredException
	    ) {
	        HttpResponse httpResponse = getHttpResponse(response, ex.getMessage(), HttpStatus.BAD_REQUEST);
	        writeResponse(response, httpResponse);
	    } else {
	        HttpResponse httpResponse = getHttpResponse(response, GENERIC_ERROR_MSG, HttpStatus.INTERNAL_SERVER_ERROR);
	        writeResponse(response, httpResponse);
	    }
	}

	/**
	 * Writes the given {@link HttpResponse} object as a JSON payload to the HTTP response output stream.
	 * <p>
	 * This method uses Jackson's {@link ObjectMapper} to serialize the {@link HttpResponse} into JSON.
	 * The serialized output is written directly to the {@link HttpServletResponse} output stream and flushed.
	 * <p>
	 * Note:
	 * <ul>
	 *     <li>If an {@link IOException} occurs during writing, it is caught and its stack trace is printed.</li>
	 *     <li>The method does not set the response status code or content type; these should be set before calling this method.</li>
	 * </ul>
	 *
	 * @param response the {@link HttpServletResponse} to write the JSON to
	 * @param httpResponse the {@link HttpResponse} object to serialize and send
	 */
	private static void writeResponse(HttpServletResponse response, HttpResponse httpResponse) {
	    try {
	        OutputStream out = response.getOutputStream();
	        ObjectMapper mapper = new ObjectMapper();
	        mapper.writeValue(out, httpResponse);
	        out.flush();
	    } catch (IOException e) {
	        e.printStackTrace();
	    }
	}

	/**
	 * Constructs a custom {@link HttpResponse} object for error handling and sets the HTTP response status and content type.
	 * <p>
	 * This method builds an {@link HttpResponse} with the current timestamp, the provided reason message,
	 * and the HTTP status code. It also sets the content type of the {@link HttpServletResponse} to
	 * {@code application/json} and sets its status code according to the provided {@link HttpStatus}.
	 * <p>
	 * Note:
	 * <ul>
	 *     <li>The {@code status} and {@code statusCode} fields in the {@link HttpResponse} are currently set to
	 *         {@link HttpStatus#INTERNAL_SERVER_ERROR} and its value, regardless of the provided {@code httpStatus}.
	 *         You may want to use {@code httpStatus} for consistency.</li>
	 *     <li>This method only prepares the {@link HttpResponse} object; writing it to the output stream
	 *         should be done using {@link #writeResponse(HttpServletResponse, HttpResponse)}.</li>
	 * </ul>
	 *
	 * @param response the {@link HttpServletResponse} to set status and content type on
	 * @param message the reason message describing the error
	 * @param httpStatus the HTTP status code to set for the response
	 * @return a constructed {@link HttpResponse} object containing the error details
	 */
	private static HttpResponse getHttpResponse(HttpServletResponse response, String message, HttpStatus httpStatus) {
	    // Build the custom error response object
	    HttpResponse httpResponse = HttpResponse.builder()
	            .timeStamp(LocalDateTime.now().toString())
	            .reason(message)
	            .status(HttpStatus.INTERNAL_SERVER_ERROR)  // Consider using httpStatus here
	            .statusCode(HttpStatus.INTERNAL_SERVER_ERROR.value())  // Consider using httpStatus.value()
	            .build();
	    
	    // Set the response content type and status code
	    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
	    response.setStatus(httpStatus.value());
	    
	    return httpResponse;
	}

}
