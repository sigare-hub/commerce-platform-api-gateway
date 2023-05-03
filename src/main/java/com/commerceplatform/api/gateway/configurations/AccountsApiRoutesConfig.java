package com.commerceplatform.api.gateway.configurations;

import com.commerceplatform.api.gateway.security.filters.JwtAuthenticationFilter;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;

@Configuration
public class AccountsApiRoutesConfig {
    private static final String API_ACCOUNTS_URI = "http://localhost:4000";

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public AccountsApiRoutesConfig(JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public RouteLocator routeLocator(RouteLocatorBuilder builder) {
        return builder.routes()
            .route("test", r -> r.method(HttpMethod.GET).and().path("/api/test").uri(API_ACCOUNTS_URI))
            .route("auth-login", r -> r.path("/api/auth/login").uri(API_ACCOUNTS_URI))
            .route("auth-validate-token", r -> r.path("/api/auth/validate-token").uri(API_ACCOUNTS_URI))
            .route("auth-recovery-password/**", r -> r.path("/api/recovery-password/**").uri(API_ACCOUNTS_URI))
            .route("role-create", r -> r.path("/api/role").filters(f -> f.filter(jwtAuthenticationFilter)).uri(API_ACCOUNTS_URI))
            .route("role-find-all", r -> r.path("/api/role").filters(f -> f.filter(jwtAuthenticationFilter)).uri(API_ACCOUNTS_URI))
            .route("user-create", r -> r.path("/api/user").filters(f -> f.filter(jwtAuthenticationFilter)).uri(API_ACCOUNTS_URI))
            .route("user-find-all", r -> r.path("/api/user").filters(f -> f.filter(jwtAuthenticationFilter)).uri(API_ACCOUNTS_URI))
            .route("users-roles-patch", r -> r.path("/api/users-roles").filters(f -> f.filter(jwtAuthenticationFilter)).uri(API_ACCOUNTS_URI))
            .build();
    }
}
