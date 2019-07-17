package org.ohdsi.authenticator.service;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.Assert;

import java.util.Date;
import java.util.HashMap;
import java.util.Objects;

@SpringBootTest
@RunWith(SpringRunner.class)
@ActiveProfiles(profiles = "test")
public class InvalidationTokenTest extends BaseTest {

    private static final String DUMMY_USERNAME = "dummy";

    @Test
    public void invalidateTokenTest() {

        String token = createDummyToken();
        Assert.isTrue(Objects.equals(DUMMY_USERNAME, authenticator.resolveUsername(token)), "Cannot resolve username from proper token");

        authenticator.invalidateToken(token);

        boolean invalidToken = false;
        try {
            authenticator.resolveUsername(token);
        } catch (AuthenticationException ex) {
            invalidToken = true;
        }

        Assert.isTrue(invalidToken, "Token was not invalidated");
    }

    private String createDummyToken() {

        return jwtTokenProvider.createToken(DUMMY_USERNAME, new HashMap<>(), new Date(new Date().getTime() + 600 * 1000));
    }
}
