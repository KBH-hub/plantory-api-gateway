package org.zero.plantoryapigatewayservice.jwt;


import java.util.List;

public class AuthInfo {

    private final Long memberId;
    private final List<String> roles;

    public AuthInfo(Long memberId, List<String> roles) {
        this.memberId = memberId;
        this.roles = roles;
    }

    public Long getMemberId() {
        return memberId;
    }

    public List<String> getRoles() {
        return roles;
    }
}

