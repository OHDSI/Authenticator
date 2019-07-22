package org.ohdsi.authenticator.service;

import lombok.var;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.ohdsi.authenticator.model.UserInfo;
import org.pac4j.core.credentials.UsernamePasswordCredentials;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.Assert;

import java.util.Objects;

@SpringBootTest
@RunWith(SpringRunner.class)
@ActiveProfiles(profiles = "test")
public class DatabaseAuthenticationTest extends BaseTest {

    private static final String METHOD = "db";

    @Test
    public void testDbAuthSuccess() {

        var authRequest = new UsernamePasswordCredentials("admin", "password");
        UserInfo userInfo = authenticator.authenticate(METHOD, authRequest);
        Assert.isTrue(
                Objects.equals(userInfo.getUsername(), authRequest.getUsername())
                        && Objects.nonNull(userInfo.getToken())
                        && Objects.equals(userInfo.getAuthMethod(), METHOD)
                        && Objects.equals(userInfo.getAdditionalInfo().get("firstName"), "Pavel")
                        && Objects.equals(userInfo.getAdditionalInfo().get("lastName"), "Grafkin"),
                "Failed to authenticate user with proper credentials"
        );
    }

    @Test
    public void testDbAuthFailure() {

        var authRequest = new UsernamePasswordCredentials("admin", "dummy");

        boolean failed = false;
        try {
            authenticator.authenticate(METHOD, authRequest);
        } catch (AuthenticationException ex) {
            failed = true;
        }

        Assert.isTrue(failed, "Authenticated user with bad credentials");
    }
}
