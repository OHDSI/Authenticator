package org.ohdsi.authenticator.service;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.ohdsi.authenticator.model.UserInfo;
import org.ohdsi.authenticator.service.authentication.provider.GoogleIapTokenProvider;
import org.ohdsi.authenticator.service.authentication.provider.GoogleIapTokenSignatureVerifier;
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
    private GoogleIapTokenSignatureVerifier googleIapTokenSignatureVerifier;

    @Before
    public void setUp() throws Exception {
        doReturn(true)
                .when(this.googleIapTokenSignatureVerifier)
                .isSignatureValid(any(), any());
    }

    @Test(expected = AuthenticationException.class)
    public void testAuthFailure() {
        UsernamePasswordCredentials authRequest = new UsernamePasswordCredentials("admin", "password");
        authenticator.authenticate(METHOD, authRequest);
    }


    @Test
    public void testResolveUser() {
        String accessToken = createAccessToken("resolve-user@email.com");

        String username = authenticator.resolveUsername(accessToken);
        Assert.assertEquals("resolve-user@email.com", username);

    }

    @Test
    public void testRefreshToken() {

        String accessToken = createAccessToken("refresh-token@email.com");

        UserInfo userInfo = authenticator.refreshToken(accessToken);
        Assert.assertEquals(accessToken, userInfo.getToken());
        Assert.assertEquals("refresh-token@email.com", userInfo.getUser().getUsername());

    }

    @Test(expected = AuthenticationException.class)
    public void testInvalidateToken() {

        String accessToken = createAccessToken("invalidate-token@email.com");
        authenticator.invalidateToken(accessToken);

        //this operation throws an exception because of token already invalid
        authenticator.resolveUsername(accessToken);
    }

    private String createAccessToken(String email) {

        String audience = String.format(GoogleIapTokenProvider.AUDIENCE_FORMAT, 42L, 42L);
        return GoogleIapTestUtils.createGoogleIapToken(audience, email);
    }
}


