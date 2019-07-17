package org.ohdsi.authenticator.service;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.Assert;

import java.util.HashMap;
import java.util.Objects;

@SpringBootTest
@RunWith(SpringRunner.class)
@ActiveProfiles(profiles = "test")
public class UserServiceTest extends BaseTest {

    private static final String USERNAME = "pgrafkin";

    @Autowired
    private UserService userService;

    @Test
    public void testUserResolvedSuccessfully() {

        String token = jwtTokenProvider.createToken(USERNAME, new HashMap<>());
        Assert.isTrue(Objects.equals(USERNAME, userService.getUser(token).getUsername()), "Cannot resolve user from token");
    }

    @Test
    public void testUserResolutionFailure() {

        String token = jwtTokenProvider.createToken(USERNAME, new HashMap<>());
        Assert.isTrue(!Objects.equals("dummy", userService.getUser(token).getUsername()), "Resolved user from wrong token");
    }
}
