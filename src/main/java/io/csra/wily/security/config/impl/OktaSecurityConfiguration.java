package io.csra.wily.security.config.impl;

import com.okta.spring.boot.oauth.Okta;
import io.csra.wily.security.service.SecurityService;
import io.csra.wily.security.service.impl.SecurityServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

public class OktaSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    public void configure(WebSecurity web) {
        web.ignoring().antMatchers(HttpMethod.OPTIONS, "/api/**");
        web.ignoring().antMatchers(
                "/api/public/**",
                "/swagger-ui.html",
                "/webjars/springfox-swagger-ui/**",
                "/swagger-resources",
                "/swagger-resources/**",
                "/v2/**",
                "/actuator",
                "/actuator/**"
        );
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().anyRequest().authenticated()
                .and()
                .oauth2ResourceServer().jwt();

        Okta.configureResourceServer401ResponseBody(http);
    }

    @Bean
    public SecurityService securityService() {
        return new SecurityServiceImpl();
    }

}
