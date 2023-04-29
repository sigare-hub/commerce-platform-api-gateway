package com.commerceplatform.api.gateway.security;

import org.springframework.http.server.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class RouteValidator {
    public static final List<String> securedEndpoints = List.of(
            "/auth/login",
            "/user",
            "/users-roles"
    );

    public boolean isSecured(ServerHttpRequest request) {
        String path = request.getURI().getPath();

        // Verifica se a rota solicitada está protegida pelo JWT
        return securedEndpoints.stream()
                .anyMatch(path::matches);
    }
}