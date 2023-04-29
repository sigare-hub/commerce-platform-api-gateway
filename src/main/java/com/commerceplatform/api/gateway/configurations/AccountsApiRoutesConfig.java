package com.commerceplatform.api.gateway.configurations;

import com.commerceplatform.api.gateway.security.filters.AuthenticationFilter;

import com.commerceplatform.api.gateway.security.filters.CsrfHeaderFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;

@Configuration
public class AccountsApiRoutesConfig {
    private static final String API_ACCOUNTS_URI = "http://localhost:4000/api";

    private AuthenticationFilter authenticationFilter;

    public AccountsApiRoutesConfig(CsrfHeaderFilter csrfHeaderFilter) {}

    @Bean
    public RouteLocator routeLocator(RouteLocatorBuilder builder, CsrfHeaderFilter csrfHeaderFilter) {
        return builder.routes()
            .route("login", r -> r.path("/auth/login")
                .filters(f -> f.filter(csrfHeaderFilter).filter(authenticationFilter))
                .uri(API_ACCOUNTS_URI))
            .route("recovery-password", r -> r.path("/recovery-password/**")
                .filters(f -> f.filter(csrfHeaderFilter).filter(authenticationFilter))
                .uri(API_ACCOUNTS_URI))
            .route("create-user", r -> r.path("/user")
//            .filters(f -> f.filter(authenticationFilter))
                .uri(API_ACCOUNTS_URI))
            .route("create-role", r -> r.method(HttpMethod.POST).and().path("/role")
                .filters(f -> f.filter(csrfHeaderFilter).filter(authenticationFilter))
                .uri(API_ACCOUNTS_URI))
            .route("get-roles", r -> r.method(HttpMethod.GET).and().path("/role")
                .filters(f -> f.filter(csrfHeaderFilter))
                .uri(API_ACCOUNTS_URI))
            .route("get-users", r -> r.method(HttpMethod.GET).and().path("/user")
                .filters(f -> f.filter(csrfHeaderFilter).filter(authenticationFilter))
                .uri(API_ACCOUNTS_URI))
            .route("get-user-types", r -> r.path("/user-type")
                .uri(API_ACCOUNTS_URI))
            .route("update-user-roles", r -> r.method(HttpMethod.PATCH).and().path("/users-roles")
                .filters(f -> f.filter(csrfHeaderFilter).filter(authenticationFilter))
                .uri(API_ACCOUNTS_URI))
            .build();
    }

}
