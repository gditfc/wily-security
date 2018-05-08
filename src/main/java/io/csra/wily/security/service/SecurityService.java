package io.csra.wily.security.service;

import io.csra.wily.security.model.UserDTO;

public interface SecurityService {

	public UserDTO getLoggedInUser();

}
