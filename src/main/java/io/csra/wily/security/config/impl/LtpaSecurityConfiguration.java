package io.csra.wily.security.config.impl;

import io.csra.wily.security.config.SecurityConfiguration;
import io.csra.wily.security.filter.AutoLoginFilter;
import io.csra.wily.security.filter.impl.LtpaAutoLoginFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The default configuration for using LtpaTokens as provided by WAS. Will use the LtpaAutoLoginFilter to extract the
 * user authentication information from the principal. Requires a web.xml to be in your application to ensure the
 * principal is populated by WAS.
 *
 * @author ndimola
 */
public class LtpaSecurityConfiguration extends SecurityConfiguration {

    private static final Logger LOGGER = LoggerFactory.getLogger(LtpaSecurityConfiguration.class);

    @Override
    protected AutoLoginFilter getAutoLoginFilter() {
        if (this.autoLoginFilter == null) {
            try {
                this.autoLoginFilter = new LtpaAutoLoginFilter(super.authenticationManagerBean());
            } catch (Exception e) {
                LOGGER.error(e.getMessage(), e);
            }
        }

        return this.autoLoginFilter;
    }

}
