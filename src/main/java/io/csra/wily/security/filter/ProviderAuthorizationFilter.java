package io.csra.wily.security.filter;

import io.csra.wily.exceptions.NotFoundException;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * This filter enables Provider-level Authorization across all endpoints by scanning the requested URL for a provider ID. If
 * one is detected, the requesting user's access will be checked to determine they are allowed to reach the requested
 * endpoint. This implementation requires that any provider-specific endpoints include the provider ID as one of the URL
 * tokens.
 *
 * @author Nick DiMola
 */
public abstract class ProviderAuthorizationFilter extends AbstractSecurityFilter {

    protected static final int PROVIDER_ID_LENGTH = 8;
    protected static final String PROVIDERS_URL_TOKEN = "providers";

    public void doFilterImpl(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) {
        Authentication principal = getPrincipal();
        isAuthorized((HttpServletRequest) servletRequest, principal);
    }

    /**
     * This method is the orchestrator for determining whether or not the current user has provider access to whatever
     * endpoint they are trying to access.
     *
     * @param request - request endpoint related to a provider
     * @param principal - authentication credentials of the user
     * @return Will always return true or result in an exception.
     * @throws AccessDeniedException - The user does not have the right access to perform the endpoint of the related provider
     * @throws NotFoundException - Provider is not found
     */
    private boolean isAuthorized(HttpServletRequest request, Authentication principal) {
        if (isUserInRoles(principal, getRolesToCheck())) {
            String providerId = getProviderIdFromUrl(request.getRequestURL().toString());

            if (!isUserAuthorizedForProvider(principal.getName(), providerId)) {
                throw new AccessDeniedException(principal.getName() + " does not have access to this provider.");
            }
        }

        return true;
    }

    /**
     * By utilizing the Spring Security Authentication information, this method will determine if the user has one of the
     * roles passed in. The current implementation is checking if the user has a provider-based role.
     *
     * @param principal - authentication credentials of the user
     * @param roles - the roles to check for
     * @return true if user has at least one role, or false if no roles
     */
    private boolean isUserInRoles(Authentication principal, String... roles) {
        for (String role : roles) {
            for (GrantedAuthority authority : principal.getAuthorities()) {
                if (role.equalsIgnoreCase(authority.getAuthority())) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * If the user is provider-based, it will reach this block of code to extract from the database which providers they are
     * linked to. If the provider being accessed isn't in their access list, this method will return false.
     *
     * @param userId - the user's id
     * @param providerId - the id of the provider in question
     * @return true if the provider is in the user access list, false if not
     */
    private boolean isUserAuthorizedForProvider(String userId, String providerId) {
        if (providerId == null) {
            return true;
        }

        List<String> providerIds = getProvidersForUser(userId);

        return providerIds.contains(providerId);
    }

    /**
     * Splits the url into tokens and determines if any of them are a provider id. This is done by inspecting each token, if
     * they appear to be a provider id (8 numeric characters), the token is run through a provider id checker. If an invalid
     * provider id is detected, a Not Found Exception will be escalated to the client.
     *
     * @param url - the url to be parsed
     * @return - the provider id from the url, if one exists
     * @throws NotFoundException - If no provider id was able to be parsed from the url
     */
    private String getProviderIdFromUrl(String url) {
        String previousUrlToken = null;

        String[] urlTokens = url.split("/");
        for (String urlToken : urlTokens) {
            if (PROVIDERS_URL_TOKEN.equalsIgnoreCase(previousUrlToken) && urlToken.length() == PROVIDER_ID_LENGTH && StringUtils.isNumeric(urlToken)) {
                if (validateProviderId(urlToken)) {
                    return urlToken;
                } else {
                    throw new NotFoundException("Provider " + urlToken + " is not found.");
                }
            }

            previousUrlToken = urlToken;
        }

        return null;
    }

    public abstract boolean validateProviderId(String providerId);

    public abstract List<String> getProvidersForUser(String userId);

    public abstract String[] getRolesToCheck();
}
