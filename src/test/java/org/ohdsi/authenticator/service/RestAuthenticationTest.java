package org.ohdsi.authenticator.service;

import lombok.var;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.ohdsi.authenticator.model.UserInfo;
import org.pac4j.core.credentials.UsernamePasswordCredentials;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

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

        AccessToken accessToken = AccessToken.jwt(userInfo.getToken());
        Assert.assertEquals("Failed to authenticate user with proper credentials", authRequest.getUsername(), userInfo.getUsername());
        Assert.assertTrue("Failed to authenticate user with proper credentials", getExpirationInSecs(accessToken) >= jwtTokenProvider.getValidityInSeconds());

    }

    @Test
    public void testRestAtlasAuthSuccess() {

        final String method = "rest-atlas";
        UsernamePasswordCredentials authRequest = new UsernamePasswordCredentials(atlasUsername, atlasPassword);
        UserInfo userInfo = authenticator.authenticate(method, authRequest);
        AccessToken accessToken = AccessToken.jwt(userInfo.getToken());
        Assert.assertEquals("Failed to authenticate user with proper credentials", authRequest.getUsername(), userInfo.getUsername());
        Assert.assertTrue("Failed to authenticate user with proper credentials", getExpirationInSecs(accessToken) >= jwtTokenProvider.getValidityInSeconds());
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

        Assert.assertTrue("Authenticated user with bad credentials", failed);
    }
}
