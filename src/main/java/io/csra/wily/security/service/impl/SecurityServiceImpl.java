package io.csra.wily.security.service.impl;

import io.csra.wily.exceptions.UnauthorizedException;
import io.csra.wily.security.model.UserDTO;
import io.csra.wily.security.service.SecurityService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.ArrayList;

public class SecurityServiceImpl implements SecurityService {

    public UserDTO getLoggedInUser() {
        UserDTO user = new UserDTO();

        Authentication principal = SecurityContextHolder.getContext().getAuthentication();

        if (principal == null) {
            throw new UnauthorizedException();
        }

        user.setUserId(principal.getName());
        user.setRoles(principal.getAuthorities());
        user.setProviderIds(new ArrayList<>());

        return user;
    }

}
