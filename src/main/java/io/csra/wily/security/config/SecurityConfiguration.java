package io.csra.wily.security.config;

import io.csra.wily.security.filter.AutoLoginFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.MethodInvokingBean;
import org.springframework.beans.factory.config.MethodInvokingFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.servlet.http.HttpServletRequest;

/**
 * Spring Security Configuration - ensures that all APIs exposed at /api/* are protected. The spring security filter
 * chain can be modified upon extending this abstract class. This will allow for the introduction of more nuanced
 * authorization.
 * 
 * @author Nick DiMola
 * 
 */
public abstract class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Autowired
	private UserDetailsService userDetailsService;

	@Autowired
	private CorsConfigurationProperties corsConfigurationProperties;

	protected AutoLoginFilter autoLoginFilter;

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

		http.authenticationProvider(authenticationProvider()).authorizeRequests()
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
				.antMatchers("/api/**").fullyAuthenticated();

		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

		http.csrf().disable();

		http.cors();

		http.addFilterAfter(getAutoLoginFilter(), SecurityContextPersistenceFilter.class);
		configureFilterChain(http);
	}

	protected void configureFilterChain(HttpSecurity http) {
		// Add other filters here
	}

	protected String getApiPath() {
		return "/api/**";
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(authenticationProvider());
	}

	@Bean
	public AuthenticationProvider authenticationProvider() {
		UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken> wrapper = new UserDetailsByNameServiceWrapper<>();
		wrapper.setUserDetailsService(userDetailsService);

		PreAuthenticatedAuthenticationProvider provider = new PreAuthenticatedAuthenticationProvider();
		provider.setPreAuthenticatedUserDetailsService(wrapper);

		return provider;
	}

	@Override
	@Bean(name = "myAuthenticationManager")
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	protected abstract AutoLoginFilter getAutoLoginFilter();

}
