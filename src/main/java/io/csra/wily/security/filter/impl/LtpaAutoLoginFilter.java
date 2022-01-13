package io.csra.wily.security.filter.impl;

import io.csra.wily.security.filter.AutoLoginFilter;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedCredentialsNotFoundException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * This spring security filter is part of the SS-Filter chain and will produce the authentication token for each request,
 * assuming the LTPA token has been processed by WAS.
 *
 * @author Nick DiMola
 */
public class LtpaAutoLoginFilter extends AutoLoginFilter {

    protected static final String ROLE_PREPEND = "ROLE_";
    protected static final String DUMMY_PASSWORD = "password";
    protected static final String OPTIONS_USER = "OPTIONS_USER";

    public LtpaAutoLoginFilter(AuthenticationManager authenticationManager) {
        super.setAuthenticationManager(authenticationManager);
    }

    /**
     * Extracts the user name from the header as provided by the IDM. If nothing is found, we pass back a null, which will
     * trigger in exception in the parent class.
     */
    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        String user = request.getUserPrincipal() != null ? request.getUserPrincipal().getName() : null;

        if (StringUtils.isNotBlank(user)) {
            return user;
        }

        // Allow OPTIONS calls through
        if (HttpMethod.OPTIONS.toString().equalsIgnoreCase(request.getMethod())) {
            return OPTIONS_USER;
        }

        return null;
    }

    /**
     * We won't have the user's password and it doesn't matter. Just using a dummy variable so Spring Security has what it
     * needs.
     */
    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        return DUMMY_PASSWORD;
    }

    /**
     * Extracts the role from the bindString which is embedded by the IDM in the header.
     *
     * @param request - the htto request
     * @return - the roles
     * @throws PreAuthenticatedCredentialsNotFoundException - thrown when credentials not found
     */
    protected List<GrantedAuthority> getRoles(HttpServletRequest request) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(ROLE_PREPEND + "USER"));
        return authorities;
    }

    /**
     * An overridden implementation of the super class method that allows the injection of a user's role. The current
     * implementation doesn't load the GrantedAuthorities from the UserDetailsService as Spring Security expects, so that we
     * can describe a user's role here.
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, Authentication authResult) throws IOException, ServletException {
        Authentication newAuth = new PreAuthenticatedAuthenticationToken(getPreAuthenticatedPrincipal(request), DUMMY_PASSWORD, getRoles(request));

        super.successfulAuthentication(request, response, newAuth);
    }

}
