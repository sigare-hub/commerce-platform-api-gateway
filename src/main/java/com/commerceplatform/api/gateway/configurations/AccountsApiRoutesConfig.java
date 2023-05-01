package com.commerceplatform.api.gateway.configurations;

import com.commerceplatform.api.gateway.security.filters.CsrfHeaderFilter;
import com.commerceplatform.api.gateway.security.filters.JwtAuthenticationFilter;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;

@Configuration
@EnableAutoConfiguration
public class AccountsApiRoutesConfig {
    private static final String API_ACCOUNTS_URI = "http://localhost:4000/api";

    @Bean
    public RouteLocator routeLocator(RouteLocatorBuilder builder) {
        return builder.routes()
            .route("test", r -> r.method(HttpMethod.GET).and().path("/test")
                    .filters(f ->
                            f.addRequestHeader("Accept", "application/json")
                        )
                    .uri(API_ACCOUNTS_URI))
            .route("login", r -> r.path("/auth/login")
                .filters(f -> f)
                .uri(API_ACCOUNTS_URI))
            .route("recovery-password", r -> r.path("/recovery-password/**")
                
                .uri(API_ACCOUNTS_URI))
            .route("create-user", r -> r.path("/user")
                
                .uri(API_ACCOUNTS_URI))
            .route("create-role", r -> r.method(HttpMethod.POST).and().path("/role")
                
                .uri(API_ACCOUNTS_URI))
            .route("get-roles", r -> r.method(HttpMethod.GET).and().path("/role")
                .filters(f -> f)
                .uri(API_ACCOUNTS_URI))
            .route("get-users", r -> r.method(HttpMethod.GET).and().path("/user")
                
                .uri(API_ACCOUNTS_URI))
            .route("get-user-types", r -> r.path("/user-type")
                .uri(API_ACCOUNTS_URI))
            .route("update-user-roles", r -> r.method(HttpMethod.PATCH).and().path("/users-roles")
                
                .uri(API_ACCOUNTS_URI))
            .build();
    }

}
