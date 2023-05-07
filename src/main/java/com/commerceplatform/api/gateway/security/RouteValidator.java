package com.commerceplatform.api.gateway.security;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class RouteValidator {
    public static final List<String> securedEndpoints = List.of(
        "/role",
        "/user",
        "/users-roles"
    );

    public boolean isSecured(ServerHttpRequest request) {
        String path = request.getURI().getPath();

        // Verifica se a rota solicitada está protegida pelo JWT
        var o = securedEndpoints.stream()
            .anyMatch(path::matches);
        return o;
    }
}