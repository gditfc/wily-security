package io.csra.wily.security.filter;

import io.csra.wily.exceptions.NotFoundException;
import io.csra.wily.exceptions.UnauthorizedException;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public abstract class AbstractSecurityFilter extends GenericFilterBean {

    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        try {
            doFilterImpl(servletRequest, servletResponse, filterChain);
            filterChain.doFilter(servletRequest, servletResponse);
        } catch (UnauthorizedException e) {
            logger.debug("Unauthorized exception. handling", e);
            handleException((HttpServletResponse) servletResponse, HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
        } catch (AccessDeniedException e) {
            logger.debug("AccessDeniedException exception. handling", e);
            handleException((HttpServletResponse) servletResponse, HttpStatus.FORBIDDEN.value(), e.getMessage());
        } catch (NotFoundException e) {
            logger.debug("NotFound exception. handling", e);
            handleException((HttpServletResponse) servletResponse, HttpStatus.NOT_FOUND.value(), e.getMessage());
        }
    }

    public abstract void doFilterImpl(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain);

    /**
     * Error handler for this filter. All exceptions should be sent here with the appropriate HTTP Status Code and message.
     *
     * @param response     - the http response
     * @param statusCode   - the status code
     * @param errorMessage - the error message
     * @throws IOException - if an input or output exception occurred
     */
    protected void handleException(HttpServletResponse response, int statusCode, String errorMessage) throws IOException {
        response.setStatus(statusCode);
        response.getWriter().println(errorMessage);
    }

    /**
     * Returns the principal. If none is found, an UnauthorizedException is escalated.
     *
     * @return - the authentication
     */
    protected Authentication getPrincipal() {
        Authentication principal = SecurityContextHolder.getContext().getAuthentication();

        if (principal == null) {
            throw new UnauthorizedException();
        }

        return principal;
    }

}
