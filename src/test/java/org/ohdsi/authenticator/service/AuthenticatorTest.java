package org.ohdsi.authenticator.service;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ohdsi.authenticator.service.authentication.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.HashMap;

@SpringBootTest
@RunWith(SpringRunner.class)
@ActiveProfiles(profiles = "test")
public class AuthenticatorTest extends BaseTest {

    private static final String USERNAME = "pgrafkin";
    @Autowired
    private UserService userService;

    @Test
    public void testUserResolvedSuccessfully() {

        String token = tokenProvider.createToken( USERNAME, new HashMap<>(), null);
        Assert.assertEquals("Cannot resolve user from token", USERNAME, userService.resolveUser(token).getUsername());
    }

    @Test
    public void testUserResolutionFailure() {

        String token = tokenProvider.createToken(USERNAME, new HashMap<>(), null);
        Assert.assertNotEquals("Resolved user from wrong token", "dummy", userService.resolveUser(token).getUsername());
    }
}
