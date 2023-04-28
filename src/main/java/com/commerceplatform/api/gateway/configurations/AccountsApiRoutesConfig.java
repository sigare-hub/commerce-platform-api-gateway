package com.commerceplatform.api.gateway.configurations;

import com.commerceplatform.api.gateway.security.filters.AuthenticationFilter;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;

@Configuration
public class AccountsApiRoutesConfig {
    private final AuthenticationFilter authenticationFilter;

    public AccountsApiRoutesConfig(AuthenticationFilter authenticationFilter) {
        this.authenticationFilter = authenticationFilter;
    }

    @Bean
    public RouteLocator routeLocator(RouteLocatorBuilder builder) {
        return builder.routes()
            .route("login", r -> r.path("/auth/login")
                .filters(f -> f.filter(authenticationFilter))
                .uri("http://localhost:4000/api"))
            .route("recovery-password", r -> r.path("/recovery-password/**")
                .filters(f -> f.filter(authenticationFilter))
                .uri("http://localhost:4000/api"))
            .route("create-user", r -> r.path("/user")
                .filters(f -> f.filter(authenticationFilter))
                .uri("http://localhost:4000/api"))
            .route("create-role", r -> r.method(HttpMethod.POST).and().path("/role")
                .filters(f -> f.filter(authenticationFilter))
                .uri("http://localhost:4000/api"))
            .route("get-roles", r -> r.method(HttpMethod.GET).and().path("/role")
                .filters(f -> f.filter(authenticationFilter))
                .uri("http://localhost:4000/api"))
            .route("get-users", r -> r.method(HttpMethod.GET).and().path("/user")
                .filters(f -> f.filter(authenticationFilter))
                .uri("http://localhost:4000/api"))
            .route("get-user-types", r -> r.path("/user-type")
                .uri("http://localhost:4000/api"))
            .route("update-user-roles", r -> r.method(HttpMethod.PATCH).and().path("/users-roles")
                .filters(f -> f.filter(authenticationFilter))
                .uri("http://localhost:4000/api"))
            .build();
    }
}
