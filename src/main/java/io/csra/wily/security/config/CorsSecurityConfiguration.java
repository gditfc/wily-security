package io.csra.wily.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

public class CorsSecurityConfiguration extends WebSecurityConfigurerAdapter {

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

}
