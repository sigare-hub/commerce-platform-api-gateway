package com.commerceplatform.api.gateway.security.filters;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class CsrfHeaderFilter implements GatewayFilter {

    private static final String CSRF_HEADER_NAME = "X-CSRF-TOKEN";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        String csrfToken = request.getCookies().getFirst(CSRF_HEADER_NAME).getValue();

        if (csrfToken != null) {
            exchange.getRequest().mutate()
                    .header(HttpHeaders.AUTHORIZATION, csrfToken)
                    .build();
        }

        return chain.filter(exchange);
    }
}
