package io.csra.wily.security.filter.impl;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import io.csra.wily.security.filter.AutoLoginFilter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedCredentialsNotFoundException;

/**
 * This spring security filter is part of the SS-Filter chain and will produce the authentication token for each request,
 * assuming it has been sent by the IDM. Both the user and bind string are expected inputs of this class via the HTTP
 * headers.
 * 
 * @author Nick DiMola
 * 
 */
public class IdmAutoLoginFilter extends AutoLoginFilter {

	private static final String ROLE_PREPEND = "ROLE_";
	private static final String AUTHENTICATION_FAILED_MESSAGE = "Authentication Failed.";
	private static final String DUMMY_PASSWORD = "password";
	private static final String USER_NAME_HEADER = "iv-user";
	private static final String ROLE_HEADER = "iv-groups";
	private static final String OPTIONS_USER = "OPTIONS_USER";

	public IdmAutoLoginFilter(AuthenticationManager authenticationManager) {
		super.setAuthenticationManager(authenticationManager);
	}

	/**
	 * Extracts the user name from the header as provided by the IDM. If nothing is found, we pass back a null, which will
	 * trigger in exception in the parent class.
	 */
	@Override
	protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
		String user = request.getHeader(USER_NAME_HEADER);

		if (StringUtils.isNotBlank(user)) {
			return user;
		}

		// Allow OPTIONS calls through
		if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
			return OPTIONS_USER;
		}

		return null;
	}

	/**
	 * We won't have the user's password and it doesn't matter. Just using a dummy variable so Spring Security has what it
	 * needs.
	 * 
	 */
	@Override
	protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
		return DUMMY_PASSWORD;
	}

	/**
	 * Extracts the role from the bindString which is embedded by the IDM in the header via the doGetRole method, which can
	 * be overriden by a sub class.
	 * 
	 * @param request
	 * @return
	 * 
	 * @throws PreAuthenticatedCredentialsNotFoundException
	 */
	private String getRole(HttpServletRequest request) {
		return doGetRole(request);
	}

	/**
	 * The true implementor of getRole. Separated to a distinct method to allow overriding by sub-classes.
	 * 
	 * @param request
	 * @return
	 */
	protected String doGetRole(HttpServletRequest request) {
		String role = request.getHeader(ROLE_HEADER);

		if (StringUtils.isNotBlank(role)) {
			role = role.replaceAll("[^A-Za-z0-9]", "");

			return ROLE_PREPEND + role.toUpperCase();
		} else {
			// Allow OPTIONS calls through
			if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
				return ROLE_PREPEND + "DOH";
			}

			throw new PreAuthenticatedCredentialsNotFoundException(AUTHENTICATION_FAILED_MESSAGE);
		}
	}

	/**
	 * An overridden implementation of the super class method that allows the injection of a user's role as passed forward
	 * from the IDM. The current implementation doesn't load the GrantedAuthorities from the UserDetailsService as Spring
	 * Security expects, so that we can describe a user's role here.
	 * 
	 */
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, Authentication authResult) throws IOException, ServletException {
		List<GrantedAuthority> authorities = new ArrayList<>();
		authorities.add(new SimpleGrantedAuthority(getRole(request)));

		Authentication newAuth = new PreAuthenticatedAuthenticationToken(getPreAuthenticatedPrincipal(request), DUMMY_PASSWORD, authorities);

		super.successfulAuthentication(request, response, newAuth);
	}

}