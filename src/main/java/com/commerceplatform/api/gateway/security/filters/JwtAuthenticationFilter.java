package com.commerceplatform.api.gateway.security.filters;

import com.auth0.jwt.interfaces.Claim;
import com.commerceplatform.api.gateway.security.RouteValidator;
import com.commerceplatform.api.gateway.security.services.JwtService;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

@Component
public class JwtAuthenticationFilter implements GatewayFilter {
    private final JwtService jwtService;
    private final RouteValidator routeValidator;

    public JwtAuthenticationFilter(JwtService jwtService, RouteValidator routeValidator) {
        this.jwtService = jwtService;
        this.routeValidator = routeValidator;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

       var request = exchange.getRequest();

        if (routeValidator.isSecured(request)) {
            String token = extractToken(request);

            if (!request.getHeaders().containsKey("Authorization")) {
                ServerHttpResponse response =  exchange.getResponse();
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                response.setComplete();
            }

            if(token == null) {
                ServerHttpResponse response = exchange.getResponse();
                response.setStatusCode(HttpStatus.BAD_REQUEST);
                return response.setComplete();
            }

            Map<String, Claim> claims = jwtService.getClaimsFromToken(token);
            List<String> roles = claims.get("roles").asList(String.class);

            exchange.getRequest().mutate().header("roles", String.valueOf(roles)).build();
        }
        return chain.filter(exchange);
    }

    private String extractToken(ServerHttpRequest request) {
        List<String> headers = request.getHeaders().get(HttpHeaders.AUTHORIZATION);
        if (headers != null && !headers.isEmpty()) {
            String header = headers.get(0);
            if (StringUtils.hasText(header) && header.startsWith("Bearer ")) {
                return header.substring(7);
            }
        }
        return null;
    }
}