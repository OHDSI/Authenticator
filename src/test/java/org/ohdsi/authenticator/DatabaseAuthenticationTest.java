package org.ohdsi.authenticator;

import lombok.var;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.ohdsi.authenticator.model.AuthenticationRequest;
import org.ohdsi.authenticator.model.UserInfo;
import org.ohdsi.authenticator.service.AuthenticationManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.Assert;

import java.util.Objects;

@SpringBootTest
@RunWith(SpringRunner.class)
@ActiveProfiles(profiles = "test")
public class DatabaseAuthenticationTest {

    private static final String METHOD = "db";

    @Autowired
    private AuthenticationManager authenticationManager;

    @Test
    public void testDbAuthSuccess() {

        var authRequest = new AuthenticationRequest("admin", "password");
        UserInfo userInfo = authenticationManager.authenticate(METHOD, authRequest);
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

        var authRequest = new AuthenticationRequest("admin", "dummy");

        boolean failed = false;
        try {
            authenticationManager.authenticate(METHOD, authRequest);
        } catch (AuthenticationException ex) {
            failed = true;
        }

        Assert.isTrue(failed, "Authenticated user with bad credentials");
    }
}
