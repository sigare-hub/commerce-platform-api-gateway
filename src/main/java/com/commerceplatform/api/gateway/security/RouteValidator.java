package com.commerceplatform.api.gateway.security;

import com.commerceplatform.api.gateway.security.services.JwtService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import java.util.List;
import java.util.function.Predicate;

@Component
public class RouteValidator {
    public static final List<String> securedEndpoints = List.of(
        "/auth/login",
        "/user",
        "/users-roles"
    );

    private final JwtService jwtService;

    public RouteValidator(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    public List<String> getSecuredEndpoints() {
        return securedEndpoints;
    }

    public void validateSecuredRoutes(ServerWebExchange exchange) {
        ServerHttpRequest request = (ServerHttpRequest) exchange.getRequest();

        Predicate<ServerHttpRequest> isApiSecured = r -> securedEndpoints.stream()
                .noneMatch(uri -> r.getURI().getPath().contains(uri));

        if(isApiSecured.test(request)) {
            if(!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                ServerHttpResponse response = (ServerHttpResponse) exchange.getResponse();
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
            }

            var token = request.getHeaders().getOrEmpty("Authorization").get(0);

            if(token == null) {
                ServerHttpResponse response = (ServerHttpResponse) exchange.getResponse();
                response.setStatusCode(HttpStatus.BAD_REQUEST);
            }

            var claims = jwtService.getClaimsFromToken(token);
            exchange.getRequest().mutate().header("id", String.valueOf(claims.get("id"))).build();

            // TODO: add JwtUtil
            //            try {
            //                jwtUtil.validateToken(token);
            //            } catch (JwtTokenMalformedException | JwtTokenMissingException e) {
            //                // e.printStackTrace();
            //
            //                ServerHttpResponse response = exchange.getResponse();
            //                response.setStatusCode(HttpStatus.BAD_REQUEST);
            //
            //                return response.setComplete();
            //            }
        }
    }

}
