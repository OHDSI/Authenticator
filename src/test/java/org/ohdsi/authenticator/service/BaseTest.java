package org.ohdsi.authenticator.service;

import java.util.Date;
import org.ohdsi.authenticator.config.AuthSchema;
import org.ohdsi.authenticator.config.AuthenticatorConfiguration;
import org.ohdsi.authenticator.service.authentication.AuthServiceProvider;
import org.ohdsi.authenticator.service.authentication.Authenticator;
import org.ohdsi.authenticator.service.authentication.TokenProvider;
import org.ohdsi.authenticator.service.authentication.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(classes = {AuthenticatorConfiguration.class, AuthSchema.class})
public class BaseTest {

    @Autowired
    protected AuthServiceProvider authServiceProvider;

    @Autowired
    protected Authenticator authenticator;

    @Autowired
    protected TokenProvider tokenProvider;

    @Autowired
    protected UserService userService;

    protected long getExpirationInSecs(String accessToken) {

        long expirationDateTimeFromToken = tokenProvider.validateTokenAndGetClaims(accessToken).getExpiration().getTime();
        return (expirationDateTimeFromToken - new Date().getTime()) / 1000;
    }
}
