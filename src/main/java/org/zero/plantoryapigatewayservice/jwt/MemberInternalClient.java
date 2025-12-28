package org.zero.plantoryapigatewayservice.jwt;

import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Component
public class MemberInternalClient {

    private final WebClient webClient; // baseUrl = member-service

    public MemberInternalClient(WebClient webClient) {
        this.webClient = webClient;
    }

    public Mono<Boolean> isStopped(Long memberId) {
        return webClient.get()
                .uri("/internal/members/{id}/status", memberId)
                .retrieve()
                .bodyToMono(MemberStatusResponse.class)
                .map(MemberStatusResponse::stopped);
    }

    public record MemberStatusResponse(Long memberId, boolean stopped) {}
}

