package org.zero.plantoryapigatewayservice.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Collections;
import java.util.List;

@Component
public class GatewayJwtVerifier {

    private final JwtProperties jwtProperties;
    private Key key;

    public GatewayJwtVerifier(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    @PostConstruct
    public void init() {
        this.key = Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes());
    }

    public AuthInfo verify(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .requireIssuer(jwtProperties.getIssuer())
                .build()
                .parseClaimsJws(token)
                .getBody();

        Long memberId = Long.valueOf(claims.getSubject());

        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) claims.get("roles");
        if (roles == null) roles = Collections.emptyList();

        return new AuthInfo(memberId, roles);
    }
}
