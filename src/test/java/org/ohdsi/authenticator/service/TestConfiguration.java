package org.ohdsi.authenticator.service;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class TestConfiguration {

    @Bean
    public TokenService tokenService(TokenProvider tokenProvider){
        return new TokenServiceImpl(tokenProvider);
    }

}
