package org.zero.plantoryapigatewayservice.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class WebClientConfig {

    @Bean
    public WebClient.Builder webClientBuilder() {
        return WebClient.builder();
    }

    @Bean
    public WebClient memberWebClient(
            WebClient.Builder builder,
            @Value("${services.member.base-url}") String baseUrl
    ) {
        return builder
                .baseUrl(baseUrl)
                .build();
    }
}
