package org.ohdsi.authenticator.config;

import org.ohdsi.authenticator.service.authentication.AuthenticationMode;
import org.ohdsi.authenticator.service.authentication.Authenticator;
import org.ohdsi.authenticator.service.authentication.authenticator.AuthenticatorProxyMode;
import org.ohdsi.authenticator.service.authentication.authenticator.AuthenticatorStandardMode;
import org.ohdsi.authenticator.service.authentication.provider.GoogleIapTokenSignatureVerifier;
import org.ohdsi.authenticator.service.authentication.provider.GoogleIapTokenVerifier;
import org.ohdsi.authenticator.service.authentication.provider.GoogleIapTokenProvider;
import org.ohdsi.authenticator.service.authentication.provider.JwtTokenProvider;
import org.ohdsi.authenticator.service.authentication.TokenProvider;
import org.ohdsi.authenticator.service.authentication.TokenService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AuthenticatorConfiguration {

    @Configuration
    @ConditionalOnProperty(value = "security.authentication.mode", havingValue = AuthenticationMode.Const.STANDARD, matchIfMissing = true)
    public class StandardMode {

        @Bean
        public Authenticator authentication(AuthSchema authSchema, TokenService tokenService, TokenProvider tokenProvider) {

            return new AuthenticatorStandardMode(authSchema, tokenService, tokenProvider);
        }

        @Bean
        public TokenProvider tokenProvider(@Value("${security.jwt.token.secretKey}") String secretKey,
                                           @Value("${security.jwt.token.validityInSeconds}") long validityInSeconds) {

            return new JwtTokenProvider(secretKey, validityInSeconds);
        }
    }

    @Configuration
    @ConditionalOnProperty(value = "security.authentication.mode", havingValue = AuthenticationMode.Const.PROXY, matchIfMissing = false)
    public class ProxyMode {
        @Bean
        public Authenticator authentication(TokenService tokenService, TokenProvider tokenProvider) {

            return new AuthenticatorProxyMode(tokenService, tokenProvider);
        }

        @Bean
        public TokenProvider tokenProvider(GoogleIapTokenVerifier googleIapTokenVerifier,
                                           @Value("${security.googleIap.cloudProjectId}") Long cloudProjectId,
                                           @Value("${security.googleIap.backendServiceId}") Long backendServiceId) {

            return new GoogleIapTokenProvider(googleIapTokenVerifier, cloudProjectId, backendServiceId);
        }

        @Bean
        public GoogleIapTokenVerifier googleIapJwtVerifier(GoogleIapTokenSignatureVerifier googleIapTokenSignatureVerifier) {

            return new GoogleIapTokenVerifier(googleIapTokenSignatureVerifier);
        }

        @Bean
        public GoogleIapTokenSignatureVerifier googleIapTokenSignatureVerifier() {

            return new GoogleIapTokenSignatureVerifier();
        }
    }

}
