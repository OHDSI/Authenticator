package org.ohdsi.authenticator.service;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.ohdsi.authenticator.model.UserInfo;
import org.ohdsi.authenticator.service.support.GoogleIapTestUtils;
import org.pac4j.core.credentials.UsernamePasswordCredentials;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

@SpringBootTest
@RunWith(SpringRunner.class)
@ActiveProfiles(profiles = { "test", "test-iap" })
public class GoogleIapAuthenticationTest extends BaseTest {

    private static final String METHOD = "iap";

    @SpyBean
    private GoogleIapJwtVerifier googleIapJwtVerifier;

    @Before
    public void setUp() throws Exception {
        doReturn(true)
                .when(this.googleIapJwtVerifier)
                .isSignatureValid(any(), any());
    }

    @Test(expected = AuthenticationException.class)
    public void testAuthFailure() {
        UsernamePasswordCredentials authRequest = new UsernamePasswordCredentials("admin", "password");
        authenticator.authenticate(METHOD, authRequest);
    }


    @Test(expected = AuthenticationException.class)
    public void testResolveAndRefreshToken() {

        String accessToken = createAccessToken();

        String username = authenticator.resolveUsername(accessToken);
        Assert.assertEquals("login@gmail.com", username);

        UserInfo userInfo = authenticator.refreshToken(accessToken);
        Assert.assertEquals(accessToken, userInfo.getToken());
        Assert.assertEquals("login@gmail.com", userInfo.getUsername());

        authenticator.invalidateToken(accessToken);

        //this operation throws an exception because of token already invalid
        authenticator.resolveUsername(accessToken);
    }

    private String createAccessToken() {

        String audience = String.format(GoogleIapTokenProvider.AUDIENCE_FORMAT, 42L, 42L);
        return GoogleIapTestUtils.createGoogleIapToken(audience);
    }
}


