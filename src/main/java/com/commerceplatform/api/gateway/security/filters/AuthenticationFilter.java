package com.commerceplatform.api.gateway.security.filters;

import com.auth0.jwt.interfaces.Claim;
import com.commerceplatform.api.gateway.security.services.JwtService;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class AuthenticationFilter implements GatewayFilter {
    private final RouteValidator routeValidator;
    private final JwtService jwtService;
    private final OAuth2AuthorizedClientManager authorizedClientManager;

    public AuthenticationFilter(RouteValidator routeValidator, JwtService jwtService, OAuth2AuthorizedClientManager authorizedClientManager) {
        this.routeValidator = routeValidator;
        this.jwtService = jwtService;
        this.authorizedClientManager = authorizedClientManager;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = (ServerHttpRequest) exchange.getRequest();

        if (routeValidator.isSecured(request)) {
            String token = extractToken(request);

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
