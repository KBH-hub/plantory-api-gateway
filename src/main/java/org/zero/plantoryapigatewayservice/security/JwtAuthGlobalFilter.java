package org.zero.plantoryapigatewayservice.security;

import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
@EnableConfigurationProperties(SecurityProperties.class)
public class JwtAuthGlobalFilter implements GlobalFilter, Ordered {

    private final SecurityProperties securityProperties;
    private final JwtUtil jwtUtil;
    private final AntPathMatcher matcher = new AntPathMatcher();

    public JwtAuthGlobalFilter(
            SecurityProperties securityProperties,
            @Value("${jwt.secret}") String secret
    ) {
        this.securityProperties = securityProperties;
        this.jwtUtil = new JwtUtil(secret);
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, org.springframework.cloud.gateway.filter.GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        // 1) whitelist면 인증 스킵
        if (isWhitelisted(path, securityProperties.getWhitelist())) {
            return chain.filter(exchange);
        }

        // 2) Authorization: Bearer <token> 파싱
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        String token = resolveBearer(authHeader);
        if (!StringUtils.hasText(token)) {
            return unauthorized(exchange);
        }

        // 3) JWT 검증 + claim 추출
        try {
            Claims claims = jwtUtil.parseClaims(token);

            // ===== 여기부터 "네 토큰 구조"에 따라 키만 맞추면 됨 =====

            // (A) userId: 보통 subject(sub)에 넣음
            String userId = claims.getSubject(); // 또는 claims.get("userId", String.class)

            // (B) roles: 예시로 roles claim이 "ROLE_USER,ROLE_ADMIN" 형태라고 가정
            // 만약 리스트 형태면 처리 로직 바꾸면 됨
            Object rolesObj = claims.get("roles");
            String roles = (rolesObj == null) ? "" : rolesObj.toString();

            // ======================================================

            // 4) 헤더 위조 방지: 기존 헤더 제거는 yml default-filters로 이미 함.
            //    여기서 "우리가" 새로 주입
            ServerWebExchange mutated = exchange.mutate()
                    .request(r -> r
                            .headers(h -> {
                                h.add("X-User-Id", userId);
                                h.add("X-Roles", roles);
                            })
                    ).build();

            return chain.filter(mutated);

        } catch (Exception e) {
            return unauthorized(exchange);
        }
    }

    private boolean isWhitelisted(String path, List<String> whitelist) {
        if (whitelist == null) return false;
        for (String pattern : whitelist) {
            if (matcher.match(pattern, path)) return true;
        }
        return false;
    }

    private String resolveBearer(String authHeader) {
        if (!StringUtils.hasText(authHeader)) return null;
        if (authHeader.startsWith("Bearer ")) return authHeader.substring(7);
        return null;
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    @Override
    public int getOrder() {
        // 라우팅보다 먼저 실행되도록 높은 우선순위
        return -100;
    }
}

