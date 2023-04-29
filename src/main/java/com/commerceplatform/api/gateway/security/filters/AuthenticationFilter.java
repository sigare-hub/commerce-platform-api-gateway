package com.commerceplatform.api.gateway.security.filters;

import com.commerceplatform.api.gateway.security.RouteValidator;
import com.commerceplatform.api.gateway.security.services.JwtService;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.security.oauth2.client.*;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

public class AuthenticationFilter implements GatewayFilter {
    private final JwtService jwtService;
    private final RouteValidator routeValidator;
    private final OAuth2AuthorizedClientManager authorizedClientManager;

    public AuthenticationFilter(JwtService jwtService, RouteValidator routeValidator, OAuth2AuthorizedClientManager authorizedClientManager) {
        this.jwtService = jwtService;
        this.routeValidator = routeValidator;
        this.authorizedClientManager = authorizedClientManager;
    }

    @Bean
    public AuthenticationFilter authenticationFilter() {
        return new AuthenticationFilter(jwtService, routeValidator, authorizedClientManager);
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = (ServerHttpRequest) exchange.getRequest();

        if (routeValidator.isSecured(request)) {
            String token = extractToken(request);

            var subject = jwtService.getSubject(token);

            if (StringUtils.hasText(token)) {
                OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId("your-client-id")
                        .principal(subject)
                        .attributes(attrs -> attrs.put(ServerWebExchange.class.getName(), exchange))
                        .build();

                OAuth2AuthorizedClient authorizedClient = authorizedClientManager.authorize(authorizeRequest);

                if (authorizedClient != null) {
                    exchange.getRequest().mutate()
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + authorizedClient.getAccessToken().getTokenValue())
                            .build();
                } else {
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                }
            } else {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }
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
