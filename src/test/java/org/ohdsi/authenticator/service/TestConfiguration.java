package org.ohdsi.authenticator.service;

import org.ohdsi.authenticator.service.authentication.TokenProvider;
import org.ohdsi.authenticator.service.authentication.TokenService;
import org.ohdsi.authenticator.service.authentication.authenticator.TokenServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class TestConfiguration {

    @Bean
    public TokenService tokenService(TokenProvider tokenProvider){
        return new TokenServiceImpl(tokenProvider);
    }

}
