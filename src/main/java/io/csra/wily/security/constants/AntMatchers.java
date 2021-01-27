package io.csra.wily.security.constants;

public class AntMatchers {

    public static final String[] PERMITTED_URLS = {
            "/api/public/**",
            "/swagger-ui/**",
            "/webjars/springfox-swagger-ui/**",
            "/swagger-resources/**",
            "/swagger-resources",
            "/v2/**",
            "/actuator",
            "/actuator/**"
    };

    public static final String[] AUTHENTICATED_URLS = {
            "/api/**"
    };

}
