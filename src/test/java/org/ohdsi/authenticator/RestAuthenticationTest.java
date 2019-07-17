package org.ohdsi.authenticator;

import lombok.var;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.ohdsi.authenticator.model.AuthenticationRequest;
import org.ohdsi.authenticator.model.UserInfo;
import org.ohdsi.authenticator.service.AuthenticationManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.Assert;

import java.util.Objects;

@SpringBootTest
@RunWith(SpringRunner.class)
@ActiveProfiles(profiles = "test")
public class RestAuthenticationTest {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Value("${credentials.rest-arachne.username}")
    private String arachneUsername;
    @Value("${credentials.rest-arachne.password}")
    private String arachnePassword;

    @Value("${credentials.rest-atlas.username}")
    private String atlasUsername;
    @Value("${credentials.rest-atlas.password}")
    private String atlasPassword;

    @Test
    public void testRestArachneAuthSuccess() {

        final var method = "rest-arachne";
        var authRequest = new AuthenticationRequest(arachneUsername, arachnePassword);
        UserInfo userInfo = authenticationManager.authenticate(method, authRequest);
        Assert.isTrue(
                Objects.equals(userInfo.getUsername(), authRequest.getUsername()),
                "Failed to authenticate user with proper credentials"
        );
    }

    @Test
    public void testRestAtlasAuthSuccess() {

        final var method = "rest-atlas";
        var authRequest = new AuthenticationRequest(atlasUsername, atlasPassword);
        UserInfo userInfo = authenticationManager.authenticate(method, authRequest);
        Assert.isTrue(
                Objects.equals(userInfo.getUsername(), authRequest.getUsername()),
                "Failed to authenticate user with proper credentials"
        );
    }

    @Test
    public void testRestAuthFailure() {

        var authRequest = new AuthenticationRequest("dummy", "dummy");

        boolean failed = false;
        try {
            authenticationManager.authenticate("rest-arachne", authRequest);
        } catch (AuthenticationException ex) {
            failed = true;
        }

        Assert.isTrue(failed, "Authenticated user with bad credentials");
    }
}
