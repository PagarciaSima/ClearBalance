package com.clear.balance.clearBalance.Utils;

import java.io.IOException;
import java.io.OutputStream;
import java.time.LocalDateTime;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;

import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.clear.balance.clearBalance.domain.HttpResponse;
import com.clear.balance.clearBalance.exeception.ApiException;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class ExceptionUtils {

	private static final String GENERIC_ERROR_MSG = "An unexpected error ocurred. Please try again later.";

	public static void processError(HttpServletRequest request, HttpServletResponse response, Exception ex) {
	   if(
			   ex instanceof ApiException || ex instanceof DisabledException 
			   || ex instanceof LockedException || ex instanceof DisabledException
			   || ex instanceof InvalidClaimException || ex instanceof TokenExpiredException
	   ) {
		   HttpResponse httpResponse = getHttpResponse(response, ex.getMessage(), HttpStatus.BAD_REQUEST);
		   writeResponse(response, httpResponse);
	   }
	   else {
		   HttpResponse httpResponse = getHttpResponse(response, GENERIC_ERROR_MSG, HttpStatus.INTERNAL_SERVER_ERROR);
		   writeResponse(response, httpResponse);
	   }
	   
		
	}

	private static void writeResponse(HttpServletResponse response, HttpResponse httpResponse) {
	    // Write the JSON response to the output stream
	    OutputStream out;
		try {
			out = response.getOutputStream();
			ObjectMapper mapper = new ObjectMapper();
		    mapper.writeValue(out, httpResponse);
		    out.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static HttpResponse getHttpResponse(HttpServletResponse response, String message, HttpStatus httpStatus) {
		// Build the custom error response object
	    HttpResponse httpResponse = HttpResponse.builder()
	            .timeStamp(LocalDateTime.now().toString())
	            .reason("You need to log in to access this resource")
	            .status(HttpStatus.UNAUTHORIZED)
	            .statusCode(HttpStatus.UNAUTHORIZED.value())
	            .build();
	    
	    // Set the response content type and status code (401 Unauthorized)
	    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
	    response.setStatus(httpStatus.value());
	    
        return httpResponse;
	}
}
