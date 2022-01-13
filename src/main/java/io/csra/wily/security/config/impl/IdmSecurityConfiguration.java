package io.csra.wily.security.config.impl;

import io.csra.wily.security.config.SecurityConfiguration;
import io.csra.wily.security.filter.AutoLoginFilter;
import io.csra.wily.security.filter.impl.IdmAutoLoginFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The default configuration for utilizing the IDM. Uses the IdmAutoLoginFilter to handle authentication/authorization.
 * Expects iv-user, iv-groups to come in the header providing both the User/Role for this application
 *
 * @author ndimola
 */
public class IdmSecurityConfiguration extends SecurityConfiguration {

    private static final Logger LOGGER = LoggerFactory.getLogger(IdmSecurityConfiguration.class);

    @Override
    protected AutoLoginFilter getAutoLoginFilter() {
        if (this.autoLoginFilter == null) {
            try {
                this.autoLoginFilter = new IdmAutoLoginFilter(super.authenticationManagerBean());
            } catch (Exception e) {
                LOGGER.error(e.getMessage(), e);
            }
        }

        return this.autoLoginFilter;
    }

}
