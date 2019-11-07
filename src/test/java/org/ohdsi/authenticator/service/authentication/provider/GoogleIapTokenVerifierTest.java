package org.ohdsi.authenticator.service.authentication.provider;

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Spy;
import org.mockito.junit.MockitoJUnitRunner;
import org.ohdsi.authenticator.exception.AuthenticationException;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.ohdsi.authenticator.service.support.GoogleIapTestUtils.createGoogleIapToken;

@RunWith(MockitoJUnitRunner.class)
public class GoogleIapTokenVerifierTest {

    public static final String TEST_AUDIENCE = "testAudience";
    public static final String USER_EMAIL = "login@gmail.com";

    @InjectMocks
    private GoogleIapTokenVerifier googleIapTokenVerifier;

    @Spy
    private GoogleIapTokenSignatureVerifier googleIapTokenSignatureVerifier;

    @Test
    public void verifyJwt_validSignature() throws Exception {
        doReturn(true)
                .when(this.googleIapTokenSignatureVerifier)
                .isSignatureValid(any(), any());

        String accessToken = createGoogleIapToken(TEST_AUDIENCE, USER_EMAIL);
        JWTClaimsSet claims = this.googleIapTokenVerifier.verifyTokenAndGetClaim(accessToken, TEST_AUDIENCE);
        String login = claims.getClaim(GoogleIapTokenVerifier.USER_EMAIL_FIELD).toString();
        assertEquals(USER_EMAIL, login);
    }

    @Test(expected = AuthenticationException.class)
    public void verifyJwt_InvalidSignature() throws Exception {
        doReturn(false)
                .when(this.googleIapTokenSignatureVerifier)
                .isSignatureValid(any(), any());

        String jwtToken = createGoogleIapToken(TEST_AUDIENCE, USER_EMAIL);
        this.googleIapTokenVerifier.verifyTokenAndGetClaim(jwtToken, TEST_AUDIENCE);
    }

}