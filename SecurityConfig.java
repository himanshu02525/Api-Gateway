package com.finance.gateway.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {

        return http
            // ✅ Disable CSRF
            .csrf(csrf -> csrf.disable())

            // ✅ Allow ALL paths temporarily
            .authorizeExchange(exchange -> exchange
                .anyExchange().permitAll()
            )

            .build();
    }
}
