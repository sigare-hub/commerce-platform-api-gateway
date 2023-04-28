package com.commerceplatform.api.gateway.configurations;

import com.commerceplatform.api.gateway.security.filters.JwtAuthenticationFilter;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.Buildable;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AccountsApiRoutesConfig {
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public AccountsApiRoutesConfig(JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public RouteLocator routeLocator(RouteLocatorBuilder builder) {
        return builder.routes()
            .route("get-roles", r ->
                (Buildable<Route>) r.path("/role")
                    .filters(f -> f
                        .filter(jwtAuthenticationFilter)
                        .filter(null))
                    .uri("http://localhost:4000/api"))
            .build();
    }
}
