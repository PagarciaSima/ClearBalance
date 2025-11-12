package com.clear.balance.clearBalance.handler;

import java.io.IOException;
import java.io.OutputStream;
import java.time.LocalDateTime;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.clear.balance.clearBalance.domain.HttpResponse;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

	/**
	 * Commences an authentication scheme. This method is called when an unauthenticated
	 * user attempts to access a protected resource, triggering an "authentication entry point".
	 * <p>
	 * It constructs a custom JSON response with a 401 Unauthorized status, instructing the user
	 * that they need to log in to gain access, and writes it to the HTTP response output stream.
	 *
	 * @param request The servlet request that caused the exception.
	 * @param response The servlet response object used to write the custom error message.
	 * @param authException The exception that was thrown, indicating that authentication failed or is required.
	 * @throws IOException If an input or output exception occurs.
	 * @throws ServletException If a servlet exception occurs.
	 */
	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
	        AuthenticationException authException) throws IOException, ServletException {
	    
	    // Log the event that an unauthenticated request was made to a protected resource
	    log.warn("Authentication required: Unauthenticated access attempt to protected resource. URI: {}", 
	             request.getRequestURI());

	    // Build the custom error response object
	    HttpResponse httpResponse = HttpResponse.builder()
	            .timeStamp(LocalDateTime.now().toString())
	            .reason("You need to log in to access this resource")
	            .status(HttpStatus.UNAUTHORIZED)
	            .statusCode(HttpStatus.UNAUTHORIZED.value())
	            .build();
	    
	    // Set the response content type and status code (401 Unauthorized)
	    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
	    response.setStatus(HttpStatus.UNAUTHORIZED.value());
	    
	    // Write the JSON response to the output stream
	    OutputStream out = response.getOutputStream();
	    ObjectMapper mapper = new ObjectMapper();
	    mapper.writeValue(out, httpResponse);
	    
	    // Ensure data is sent
	    out.flush();
	    log.debug("Successfully sent 401 Unauthorized response to client.");
	}

}
