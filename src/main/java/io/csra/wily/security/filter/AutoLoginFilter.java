package io.csra.wily.security.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.Enumeration;

/**
 * This spring security filter is part of the SS-Filter chain and will produce the authentication token for each request,
 * assuming the LTPA token has been processed by WAS.
 *
 * @author Nick DiMola
 */
public abstract class AutoLoginFilter extends AbstractPreAuthenticatedProcessingFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(AutoLoginFilter.class);
    private static final String ROW_OF_PLUSES = "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++";

    protected void logRequestDetails(HttpServletRequest request) {
        LOGGER.info(ROW_OF_PLUSES);
        LOGGER.info("++                     Request Details                           ++");
        LOGGER.info(ROW_OF_PLUSES);
        String method = String.format("Method: %s", request.getMethod());
        LOGGER.info(method);
        String user = String.format("User: %s", (request.getUserPrincipal() != null ? request.getUserPrincipal().getName() : "No User Principal"));
        LOGGER.info(user);
        String authType = String.format("Auth Type: %s", (request.getAuthType() != null ? request.getAuthType() : "No Auth Type"));
        LOGGER.info(authType);
        LOGGER.info(ROW_OF_PLUSES);

        LOGGER.info("");

        LOGGER.info(ROW_OF_PLUSES);
        LOGGER.info("++                         Attributes                            ++");
        LOGGER.info(ROW_OF_PLUSES);
        Enumeration<String> enNames = request.getAttributeNames();
        while (enNames.hasMoreElements()) {
            String param = enNames.nextElement();
            String paramAndAttribute = param + " - " + request.getAttribute(param);
            LOGGER.info(paramAndAttribute);
        }
        LOGGER.info(ROW_OF_PLUSES);

        LOGGER.info("");

        LOGGER.info(ROW_OF_PLUSES);
        LOGGER.info("++                          Headers                              ++");
        LOGGER.info(ROW_OF_PLUSES);

        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            String headerValue = request.getHeader(headerName);
            String headerNameAndValue = String.format("%s-%s", headerName, headerValue);

            LOGGER.info(headerNameAndValue);
        }
        LOGGER.info(ROW_OF_PLUSES);

        LOGGER.info("");

        LOGGER.info(ROW_OF_PLUSES);
        LOGGER.info("++                          Cookies                              ++");
        LOGGER.info(ROW_OF_PLUSES);

        if (request.getCookies() != null) {
            int i = 1;
            for (Cookie cookie : request.getCookies()) {
                String cookieNumber = "Cookie #" + i;
                String cookieDomain = "Domain: " + cookie.getDomain();
                String cookieName = "Name: " + cookie.getName();
                String cookieValue = "Value: " + cookie.getValue();
                String cookiePath = "Path: " + cookie.getPath();
                LOGGER.info(cookieNumber);
                LOGGER.info(cookieDomain);
                LOGGER.info(cookieName);
                LOGGER.info(cookieValue);
                LOGGER.info(cookiePath);
                LOGGER.info("");
                i++;
            }
        }

        LOGGER.info(ROW_OF_PLUSES);
    }
}
