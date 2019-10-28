package org.ohdsi.authenticator.service;

import lombok.var;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.ohdsi.authenticator.model.UserInfo;
import org.pac4j.core.credentials.UsernamePasswordCredentials;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.Assert;

import java.util.Objects;

@SpringBootTest
@RunWith(SpringRunner.class)
@ActiveProfiles(profiles = "test")
public class RestAuthenticationTest extends BaseTest {

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
        var authRequest = new UsernamePasswordCredentials(arachneUsername, arachnePassword);
        UserInfo userInfo = authenticator.authenticate(method, authRequest);
        Assert.isTrue(
                Objects.equals(userInfo.getUsername(), authRequest.getUsername())
                && getExpirationInSecs(userInfo.getToken()) >= jwtTokenProvider.getValidityInSeconds(),
                "Failed to authenticate user with proper credentials"
        );
    }

    @Test
    public void testRestAtlasAuthSuccess() {

        final var method = "rest-atlas";
        var authRequest = new UsernamePasswordCredentials(atlasUsername, atlasPassword);
        UserInfo userInfo = authenticator.authenticate(method, authRequest);
        Assert.isTrue(
                Objects.equals(userInfo.getUsername(), authRequest.getUsername())
                && getExpirationInSecs(userInfo.getToken()) <= jwtTokenProvider.getValidityInSeconds(),
                "Failed to authenticate user with proper credentials"
        );
    }

    @Test
    public void testRestAuthFailure() {

        var authRequest = new UsernamePasswordCredentials("dummy", "dummy");

        boolean failed = false;
        try {
            authenticator.authenticate("rest-arachne", authRequest);
        } catch (AuthenticationException ex) {
            failed = true;
        }

        Assert.isTrue(failed, "Authenticated user with bad credentials");
    }
}
