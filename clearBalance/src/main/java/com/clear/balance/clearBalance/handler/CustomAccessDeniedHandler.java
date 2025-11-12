package com.clear.balance.clearBalance.handler;

import java.io.IOException;
import java.io.OutputStream;
import java.time.LocalDateTime;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import com.clear.balance.clearBalance.domain.HttpResponse;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

	/**
	 * Handles {@link AccessDeniedException} when an authenticated user attempts to access a resource
	 * for which they lack the necessary permissions (e.g., they are logged in but lack the required role).
	 * <p>
	 * This method constructs a custom JSON response with a 403 Forbidden status, detailing the reason
	 * for access denial, and writes it directly to the HTTP response output stream.
	 *
	 * @param request The servlet request that resulted in the exception.
	 * @param response The servlet response object used to write the custom error message.
	 * @param accessDeniedException The exception thrown by the framework indicating permission denial.
	 * @throws IOException If an input or output exception occurs.
	 * @throws ServletException If a servlet exception occurs.
	 */
	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
	        AccessDeniedException accessDeniedException) throws IOException, ServletException {

	    // Log the denial of access attempt
	    log.warn("Access Denied: User attempted to access protected resource without required permissions. URI: {}", 
	             request.getRequestURI());

	    // Build the custom error response object
	    HttpResponse httpResponse = HttpResponse.builder()
	            .timeStamp(LocalDateTime.now().toString())
	            .reason("You do not have permission to access this resource")
	            .status(HttpStatus.FORBIDDEN)
	            .statusCode(HttpStatus.FORBIDDEN.value())
	            .build();
	    
	    // Set the response content type and status code
	    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
	    response.setStatus(HttpStatus.FORBIDDEN.value());
	    
	    // Write the JSON response to the output stream
	    OutputStream out = response.getOutputStream();
	    ObjectMapper mapper = new ObjectMapper();
	    mapper.writeValue(out, httpResponse);
	    
	    // Ensure data is sent
	    out.flush();
	    log.debug("Successfully sent 403 Forbidden response to client.");
	}

}
