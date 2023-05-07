package com.commerceplatform.api.gateway.security;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;

@Component
public class RouteValidator {
    public static final List<String> securedEndpoints = Arrays.asList(
        "/role:get",
        "/role:post",
        "/user:get",
        "/user:post",
        "/users-roles:patch",
        "/product:post"
    );

    public boolean isSecured(ServerHttpRequest request) {
        String path = request.getURI().getPath().replace("/api", "");
        String method = request.getMethod().name().toLowerCase();
        String endpointAndMethod = path + ":" + method;
        return securedEndpoints.contains(endpointAndMethod);
    }
}