package com.commerceplatform.api.gateway.security.filters;

import com.auth0.jwt.interfaces.Claim;
import com.commerceplatform.api.gateway.security.RouteValidator;
import com.commerceplatform.api.gateway.security.services.JwtService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;

import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.List;
import java.util.Map;

@Component
public class JwtAuthenticationFilter implements GatewayFilter {
    private final JwtService jwtService;
    private final RouteValidator routeValidator;

    @Autowired
    private WebClient.Builder webClientBuilder;

    public JwtAuthenticationFilter(JwtService jwtService, RouteValidator routeValidator) {
        this.jwtService = jwtService;
        this.routeValidator = routeValidator;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

       var request = exchange.getRequest();

        if (Boolean.FALSE.equals(routeValidator.isSecured(request))) {

            String token = extractToken(request);
            if(token == null) {
                ServerHttpResponse response = exchange.getResponse();
                response.setStatusCode(HttpStatus.BAD_REQUEST);
                response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
                String message = "Voce deseja solicitar uma rota protegida, mas não forneceu um token.";
                return response.writeAndFlushWith(Mono.just(
                        Mono.just(response.bufferFactory().wrap(message.getBytes()))
                ));
            }

            System.out.println(token);

//            if(token == null) {
//                System.out.println("nao tem token");
//                ServerHttpResponse response = exchange.getResponse();
//                response.setStatusCode(HttpStatus.BAD_REQUEST);
//                response.setComplete();
//            }
//
//            if (!request.getHeaders().containsKey("Authorization")) {
//                ServerHttpResponse response =  exchange.getResponse();
//                response.setStatusCode(HttpStatus.UNAUTHORIZED);
//                response.setComplete();
//            }
//
//            try {
//                URI uri = URI.create("http://localhost:4000/api/auth/validate-token?token="+token);
//                WebClient webClient = webClientBuilder.build();
//                webClient.get()
//                        .uri(uri)
//                        .retrieve()
//                        .bodyToMono(Object.class)
//                        .flatMap(responseBody -> {
//                            ServerHttpResponse response = exchange.getResponse();
//                            response.setStatusCode(HttpStatus.OK);
//                            response.getHeaders().add("Content-Type", "application/json");
//                            return Mono.just(responseBody);
//                        });
//            } catch(Exception e) {
//                throw new RuntimeException(e.getMessage());
//            }
//
//            Map<String, Claim> claims = jwtService.getClaimsFromToken(token);
//            List<String> roles = claims.get("roles").asList(String.class);
//
//            exchange.getRequest().mutate().header("roles", String.valueOf(roles)).build();
        }
        return chain.filter(exchange);
    }

    private String extractToken(ServerHttpRequest request) throws RuntimeException{
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