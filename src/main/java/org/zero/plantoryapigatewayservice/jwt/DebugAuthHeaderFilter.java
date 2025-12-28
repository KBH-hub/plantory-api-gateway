//package org.zero.plantoryapigatewayservice.jwt;
//
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.cloud.gateway.filter.GatewayFilterChain;
//import org.springframework.cloud.gateway.filter.GlobalFilter;
//import org.springframework.stereotype.Component;
//import org.springframework.web.server.ServerWebExchange;
//import reactor.core.publisher.Mono;
//
//@Component
//public class DebugAuthHeaderFilter implements GlobalFilter {
//    private static final Logger log = LoggerFactory.getLogger(DebugAuthHeaderFilter.class);
//
//    @Override
//    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
//        String auth = exchange.getRequest().getHeaders().getFirst("Authorization");
//        log.info("Auth Header: {}", auth);
//        return chain.filter(exchange);
//    }
//}
