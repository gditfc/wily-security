package io.csra.wily.security.config.impl;

import com.okta.spring.boot.oauth.Okta;
import io.csra.wily.security.config.CorsSecurityConfiguration;
import io.csra.wily.security.constants.AntMatchers;
import io.csra.wily.security.service.SecurityService;
import io.csra.wily.security.service.impl.SecurityServiceImpl;
import org.springframework.beans.factory.config.MethodInvokingBean;
import org.springframework.beans.factory.config.MethodInvokingFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;

public class OktaSecurityConfiguration extends CorsSecurityConfiguration {

    @Bean
    public MethodInvokingBean methodInvokingFactoryBean() {
        MethodInvokingBean methodInvokingBean = new MethodInvokingFactoryBean();
        methodInvokingBean.setTargetClass(SecurityContextHolder.class);
        methodInvokingBean.setTargetMethod("setStrategyName");
        methodInvokingBean.setArguments(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
        return methodInvokingBean;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.authorizeRequests()
                .antMatchers(
                    AntMatchers.PERMITTED_URLS
                ).permitAll()
                .antMatchers(
                    AntMatchers.AUTHENTICATED_URLS
                ).fullyAuthenticated()
                .and()
                .oauth2ResourceServer().jwt();

        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.csrf().disable();

        http.cors();

        Okta.configureResourceServer401ResponseBody(http);
    }

    @Bean
    public SecurityService securityService() {
        return new SecurityServiceImpl();
    }

}
