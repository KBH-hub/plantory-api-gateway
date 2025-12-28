package org.zero.plantoryapigatewayservice.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.zero.plantoryapigatewayservice.jwt.JwtProvider;
import org.zero.plantoryapigatewayservice.security.SecurityProperties;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

@Component
public class JwtGlobalFilter implements GlobalFilter, Ordered {

    private static final String HDR_USER_ID = "X-User-Id";
    private static final String HDR_ROLES = "X-Roles";
    private static final String HDR_AUTH_SOURCE = "X-Auth-Source";
    private static final String AUTH_SOURCE_VALUE = "gateway";

    private final JwtProvider jwtProvider;
    private final SecurityProperties securityProperties;
    private final AntPathMatcher matcher = new AntPathMatcher();

    public JwtGlobalFilter(JwtProvider jwtProvider, SecurityProperties securityProperties) {
        this.jwtProvider = jwtProvider;
        this.securityProperties = securityProperties;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        final String path = exchange.getRequest().getURI().getPath();

        if (HttpMethod.OPTIONS.equals(exchange.getRequest().getMethod())) {
            return chain.filter(exchange);
        }

        if (isWhitelisted(path)) {
            ServerHttpRequest sanitized = exchange.getRequest().mutate()
                    .headers(h -> {
                        h.remove(HDR_USER_ID);
                        h.remove(HDR_ROLES);
                        h.remove(HDR_AUTH_SOURCE);
                    })
                    .build();
            return chain.filter(exchange.mutate().request(sanitized).build());
        }

        String token = resolveBearer(exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION));
        if (!StringUtils.hasText(token)) {
            return writeError(exchange, HttpStatus.UNAUTHORIZED, "AUTH-401", "인증 필요", "Bearer 토큰이 없습니다.");
        }

        final Claims claims;
        try {
            claims = jwtProvider.parseClaims(token);
        } catch (JwtException | IllegalArgumentException e) {
            return writeError(exchange, HttpStatus.UNAUTHORIZED, "AUTH-401", "인증 실패", "유효하지 않은 토큰입니다.");
        }

        String status = safeString(claims.get("status"));
        if (StringUtils.hasText(status) && !"ACTIVE".equalsIgnoreCase(status)) {
            return writeError(exchange, HttpStatus.FORBIDDEN, "AUTH-403", "접근 불가", "사용자 상태가 유효하지 않습니다.");
        }

        String memberId = safeString(claims.getSubject());
        if (!StringUtils.hasText(memberId)) {
            return writeError(exchange, HttpStatus.UNAUTHORIZED, "AUTH-401", "인증 실패", "토큰 subject가 비어있습니다.");
        }

        String rolesHeader = normalizeRolesHeader(claims.get("roles"));

        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .headers(h -> {
                    // 선택: 다운스트림이 토큰을 직접 보지 못하게 하려면 Authorization 제거
                    h.remove(HttpHeaders.AUTHORIZATION);

                    h.remove(HDR_USER_ID);
                    h.remove(HDR_ROLES);
                    h.remove(HDR_AUTH_SOURCE);

                    h.add(HDR_USER_ID, memberId);
                    if (StringUtils.hasText(rolesHeader)) {
                        h.add(HDR_ROLES, rolesHeader);
                    }
                    h.add(HDR_AUTH_SOURCE, AUTH_SOURCE_VALUE);
                })
                .build();

        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    private boolean isWhitelisted(String path) {
        List<String> whitelist = securityProperties.getWhitelist();
        if (whitelist == null || whitelist.isEmpty()) return false;

        for (String pattern : whitelist) {
            if (!StringUtils.hasText(pattern)) continue;
            if (matcher.match(pattern.trim(), path)) return true;
        }
        return false;
    }

    private String resolveBearer(String authHeader) {
        if (!StringUtils.hasText(authHeader)) return null;
        if (authHeader.startsWith("Bearer ")) return authHeader.substring(7).trim();
        return null;
    }

    private String normalizeRolesHeader(Object rolesClaim) {
        if (rolesClaim == null) return "";

        final List<String> roles;

        if (rolesClaim instanceof Collection<?> c) {
            roles = c.stream()
                    .filter(Objects::nonNull)
                    .map(Object::toString)
                    .map(String::trim)
                    .filter(StringUtils::hasText)
                    .collect(Collectors.toList());
        } else {
            String s = rolesClaim.toString().trim();
            if (!StringUtils.hasText(s)) return "";
            roles = Arrays.stream(s.split(","))
                    .map(String::trim)
                    .filter(StringUtils::hasText)
                    .collect(Collectors.toList());
        }

        List<String> normalized = roles.stream()
                .map(r -> r.startsWith("ROLE_") ? r : "ROLE_" + r)
                .distinct()
                .toList();

        return String.join(",", normalized);
    }

    private String safeString(Object v) {
        return v == null ? "" : v.toString().trim();
    }

    private Mono<Void> writeError(ServerWebExchange exchange,
                                  HttpStatus status,
                                  String code,
                                  String title,
                                  String message) {

        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String path = exchange.getRequest().getURI().getPath();
        String body = """
                {
                  "code": "%s",
                  "title": "%s",
                  "message": "%s",
                  "path": "%s",
                  "status": %d
                }
                """.formatted(code, title, message, path, status.value());

        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
    }

    @Override
    public int getOrder() {
        return -100;
    }
}
