package com.commerceplatform.api.gateway.security.filters;

import com.auth0.jwt.interfaces.Claim;
import com.commerceplatform.api.gateway.security.RouteValidator;
import com.commerceplatform.api.gateway.security.services.JwtService;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
//import org.springframework.http.HttpHeaders;
//import org.springframework.http.server.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class JwtAuthenticationFilter implements GatewayFilter {
    private final JwtService jwtService;
    private final RouteValidator routeValidator;

    public JwtAuthenticationFilter(JwtService jwtService, RouteValidator routeValidator) {
        this.jwtService = jwtService;
        this.routeValidator = routeValidator;
    }

    private void authenticateByToken(String token) {
        var subject = jwtService.getSubject(token);
        Map<String, Claim> claims = jwtService.getClaimsFromToken(token);
        List<String> roles = (List<String>) claims.get("roles");

        if(roles != null && !roles.isEmpty()) {
            List<GrantedAuthority> authorities = roles.stream()
                .map(role -> new SimpleGrantedAuthority(role))
                .collect(Collectors.toList());

            Authentication authentication = new UsernamePasswordAuthenticationToken(subject, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
    }

    private String getHeaderToken(String token) {
        if (StringUtils.hasText(token) && token.startsWith("Bearer ")) {
            return token.substring(7);
        }
        return null;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        routeValidator.validateSecuredRoutes(exchange);
        return chain.filter(exchange);
        //
//        var authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
//        var token = getHeaderToken(authHeader);
//
//        if(StringUtils.hasText(token) && token != null) {
//            authenticateByToken(token);
//        }
    }
}
