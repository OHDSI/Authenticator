package org.ohdsi.authenticator.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.ohdsi.authenticator.model.UserInfo;
import org.ohdsi.authenticator.service.authentication.provider.JwtTokenProvider;
import org.pac4j.core.credentials.UsernamePasswordCredentials;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

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

    @Autowired
    protected JwtTokenProvider jwtTokenProvider;

    @Test
    public void testRestArachneAuthSuccess() {

        final String method = "rest-arachne";
        UsernamePasswordCredentials authRequest = new UsernamePasswordCredentials(arachneUsername, arachnePassword);
        UserInfo userInfo = authenticator.authenticate(method, authRequest);

        String accessToken = userInfo.getToken();
        assertEquals("Failed to authenticate user with proper credentials", authRequest.getUsername(), userInfo.getUsername());
        assertTrue("Failed to authenticate user with proper credentials", getExpirationInSecs(accessToken) >= jwtTokenProvider.getValidityInSeconds());

    }

    @Test
    public void testRestAtlasAuthSuccess() {

        final String method = "rest-atlas";
        UsernamePasswordCredentials authRequest = new UsernamePasswordCredentials(atlasUsername, atlasPassword);
        UserInfo userInfo = authenticator.authenticate(method, authRequest);
        String accessToken = userInfo.getToken();
        assertEquals("Failed to authenticate user with proper credentials", authRequest.getUsername(), userInfo.getUsername());
        assertTrue("Failed to authenticate user with proper credentials", jwtTokenProvider.getValidityInSeconds() >= getExpirationInSecs(accessToken));
    }

    @Test
    public void testRestAuthFailure() {

        UsernamePasswordCredentials authRequest = new UsernamePasswordCredentials("dummy", "dummy");

        boolean failed = false;
        try {
            authenticator.authenticate("rest-arachne", authRequest);
        } catch (AuthenticationException ex) {
            failed = true;
        }

        assertTrue("Authenticated user with bad credentials", failed);
    }
}
