package com.clear.balance.clearBalance.Utils;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import nl.basjes.parse.useragent.UserAgent;
import nl.basjes.parse.useragent.UserAgentAnalyzer;

@Slf4j
public class RequestUtils {

    private static final String UNKNOWN_IP = "Unknown IP";
	private static final String X_FORWARDED_FOR_HEADER = "X-Forwarded-For";
	private static final String USER_AGENT_HEADER = "User-Agent";

	/**
     * Retrieves the client's IP address from the given {@link HttpServletRequest}.
     *
     * <p>The method first checks the "X-Forwarded-For" HTTP header, which is commonly
     * set by proxies or load balancers to indicate the original client IP. If this header
     * is missing, empty, or marked as "unknown", the method falls back to
     * {@link HttpServletRequest#getRemoteAddr()}, which returns the IP address directly
     * seen by the servlet container.
     *
     * @param request the {@link HttpServletRequest} from which to extract the IP address
     * @return the client's IP address as a {@link String}, or "Unknown IP" if the request is null
     */
    public static String getIpAddress(HttpServletRequest request) {
        String ipAddress = UNKNOWN_IP;

        if (request != null) {
            // Try to get IP from X-Forwarded-For header (set by proxies/load balancers)
            ipAddress = request.getHeader(X_FORWARDED_FOR_HEADER);
            log.debug("X-Forwarded-For header: {}", ipAddress);

            // Fallback to remote address if header is missing or unknown
            if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
                ipAddress = request.getRemoteAddr();
                log.debug("Using getRemoteAddr(): {}", ipAddress);
            }
        } else {
            log.warn("HttpServletRequest is null, returning 'Unknown IP'");
        }

        log.info("Detected client IP: {}", ipAddress);
        return ipAddress;
    }
	
    /**
     * Retrieves the client's device information (browser and device type) from the HTTP request.
     *
     * <p>This method parses the "User-Agent" header using {@link UserAgentAnalyzer} to
     * determine the browser (agent name) and device type. It caches results to improve
     * performance and hides internal matcher load statistics for cleaner output.
     *
     * @param request the {@link HttpServletRequest} containing the User-Agent header
     * @return a string in the format "Browser - Device" (e.g., "Chrome - Desktop")
     */
    public static String getDevice(HttpServletRequest request) {
        // Build a UserAgentAnalyzer with caching and without loading stats
        UserAgentAnalyzer userAgentAnalyzer = UserAgentAnalyzer.newBuilder()
                .hideMatcherLoadStats()    // Prevent matcher load logs from appearing
                .withCache(10000)          // Cache up to 10,000 parsed User-Agent results
                .build();

        // Extract the User-Agent header from the request
        String userAgentHeader = request.getHeader(USER_AGENT_HEADER);
        log.debug("Parsing User-Agent header: {}", userAgentHeader);

        // Parse the User-Agent string
        UserAgent agent = userAgentAnalyzer.parse(userAgentHeader);

        // Extract browser and device information
        String browser = agent.getValue(UserAgent.AGENT_NAME);
        String device = agent.getValue(UserAgent.DEVICE_NAME);
        String result = browser + " - " + device;

        log.info("Detected client device: {}", result);

        return result;
    }
}
