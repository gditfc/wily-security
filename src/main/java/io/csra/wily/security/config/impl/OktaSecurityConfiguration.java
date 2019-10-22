package io.csra.wily.security.config.impl;

import com.okta.spring.boot.oauth.Okta;
import io.csra.wily.security.config.CorsConfigurationProperties;
import io.csra.wily.security.service.SecurityService;
import io.csra.wily.security.service.impl.SecurityServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.MethodInvokingBean;
import org.springframework.beans.factory.config.MethodInvokingFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

public class OktaSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private CorsConfigurationProperties corsConfigurationProperties;

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfig = new CorsConfiguration();
        corsConfig.setAllowCredentials(true);
        corsConfig.setAllowedOrigins(corsConfigurationProperties.getOrigin());
        corsConfig.setAllowedMethods(corsConfigurationProperties.getMethods());
        corsConfig.setAllowedHeaders(corsConfigurationProperties.getAllowheaders());
        corsConfig.setExposedHeaders(corsConfigurationProperties.getExposeheaders());
        corsConfig.setMaxAge(corsConfigurationProperties.getMaxage());

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig);

        return source;
    }

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
                        "/api/public/**",
                        "/swagger-ui.html",
                        "/webjars/springfox-swagger-ui/**",
                        "/swagger-resources/**",
                        "/swagger-resources",
                        "/v2/**",
                        "/actuator",
                        "/actuator/**"
                ).anonymous()
                .antMatchers("/api/**").fullyAuthenticated()
                .and()
                .oauth2ResourceServer().jwt();

        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.csrf().disable();

        http.cors();

        configureFilterChain(http);

        Okta.configureResourceServer401ResponseBody(http);
    }

    protected void configureFilterChain(HttpSecurity http) {
        // Add other filters here
    }

    @Bean
    public SecurityService securityService() {
        return new SecurityServiceImpl();
    }

}
