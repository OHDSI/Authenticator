package org.ohdsi.authenticator.service;

import java.util.Date;
import org.ohdsi.authenticator.config.AuthenticatorConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(classes = {TestConfiguration.class, AuthenticatorConfiguration.class})
public class BaseTest {

    @Autowired
    protected Authenticator authenticator;

    @Autowired
    protected TokenProvider tokenProvider;

    protected long getExpirationInSecs(String accessToken) {

        long expirationDateTimeFromToken = tokenProvider.validateTokenAndGetClaims(accessToken).getExpiration().getTime();
        return (expirationDateTimeFromToken - new Date().getTime()) / 1000;
    }
}
