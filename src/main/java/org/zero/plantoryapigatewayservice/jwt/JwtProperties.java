package org.zero.plantoryapigatewayservice.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;


@Component
@ConfigurationProperties("jwt")
public class JwtProperties {
    private String issuer;
    private String secret;
    private long accessTokenExpiration;

    public void setRefreshTokenExpiration(long refreshTokenExpiration) {
        this.refreshTokenExpiration = refreshTokenExpiration;
    }

    public void setAccessTokenExpiration(long accessTokenExpiration) {
        this.accessTokenExpiration = accessTokenExpiration;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    private long refreshTokenExpiration;

    public String getIssuer() {
        return issuer;
    }

    public String getSecret() {
        return secret;
    }

    public long getAccessTokenExpiration() {
        return accessTokenExpiration;
    }

    public long getRefreshTokenExpiration() {
        return refreshTokenExpiration;
    }
}
