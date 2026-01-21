package org.zero.plantoryapigatewayservice.jwt;

import io.jsonwebtoken.JwtException;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
public class AuthenticationGlobalFilter implements GlobalFilter, Ordered {

    private final GatewayJwtVerifier jwtVerifier;
    private final MemberInternalClient memberInternalClient;

    private static final List<String> WHITELIST_PREFIX = List.of(
            "/swagger-ui",
            "/v3/api-docs",
            "/api/auth",
            "/api/members",
            "/actuator"
    );

    public AuthenticationGlobalFilter(GatewayJwtVerifier jwtVerifier, MemberInternalClient memberInternalClient) {
        this.jwtVerifier = jwtVerifier;
        this.memberInternalClient = memberInternalClient;
    }

    @Override
    public int getOrder() {
        return -100;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        if (isWhitelisted(path)) {
            return chain.filter(exchange);
        }

        String token = resolveBearerToken(exchange.getRequest().getHeaders().getFirst("Authorization"));
        if (token == null) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        final AuthInfo authInfo;
        try {
            authInfo = jwtVerifier.verify(token);
        } catch (JwtException | IllegalArgumentException e) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        return memberInternalClient.isStopped(authInfo.getMemberId())
                .flatMap(stopped -> {
                    if (stopped) {
                        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                        exchange.getResponse().getHeaders().add("X-GW-Blocked-By", "stopped-check");
                        return exchange.getResponse().setComplete();
                    }

                    ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                            .headers(h -> {
                                h.set("X-Auth-UserId", String.valueOf(authInfo.getMemberId()));

                                h.remove("X-Auth-Roles");
                                if (authInfo.getRoles() != null && !authInfo.getRoles().isEmpty()) {
                                    String rolesHeader = authInfo.getRoles().stream()
                                            .filter(r -> r != null && !r.isBlank())
                                            .map(r -> r.startsWith("ROLE_") ? r : "ROLE_" + r)
                                            .distinct()
                                            .reduce((a, b) -> a + "," + b)
                                            .orElse(null);

                                    if (rolesHeader != null) h.set("X-Auth-Roles", rolesHeader);
                                }
                            })
                            .build();

                    return chain.filter(exchange.mutate().request(mutatedRequest).build());
                })
                .onErrorResume(e -> {
                    exchange.getResponse().setStatusCode(HttpStatus.SERVICE_UNAVAILABLE);
                    exchange.getResponse().getHeaders().add("X-GW-Blocked-By", "member-status-error");
                    return exchange.getResponse().setComplete();
                });

    }

    private boolean isWhitelisted(String path) {
        return WHITELIST_PREFIX.stream().anyMatch(path::startsWith);
    }

    private String resolveBearerToken(String authorization) {
        if (authorization == null) return null;
        if (!authorization.startsWith("Bearer ")) return null;
        return authorization.substring(7).trim();
    }
}
