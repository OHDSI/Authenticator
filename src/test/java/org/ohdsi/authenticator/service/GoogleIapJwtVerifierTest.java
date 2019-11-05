package org.ohdsi.authenticator.service;

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Spy;
import org.mockito.junit.MockitoJUnitRunner;
import org.ohdsi.authenticator.exception.AuthenticationException;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.ohdsi.authenticator.service.support.GoogleIapTestUtils.createGoogleIapToken;

@RunWith(MockitoJUnitRunner.class)
public class GoogleIapJwtVerifierTest {

    public static final String TEST_AUDIENCE = "testAudience";
    @Spy
    private GoogleIapJwtVerifier googleIapJwtVerifier;

    @Test
    public void verifyJwt_validSignature() throws Exception {
        doReturn(true)
                .when(this.googleIapJwtVerifier)
                .isSignatureValid(any(), any());

        String accessToken = createGoogleIapToken(TEST_AUDIENCE);
        JWTClaimsSet claims = this.googleIapJwtVerifier.verifyJwt(accessToken, TEST_AUDIENCE);
        String login = claims.getClaim(GoogleIapJwtVerifier.USER_EMAIL_FIELD).toString();
        assertEquals("login@gmail.com", login);
    }

    @Test(expected = AuthenticationException.class)
    public void verifyJwt_InvalidSignature() throws Exception {
        doReturn(false)
                .when(this.googleIapJwtVerifier)
                .isSignatureValid(any(), any());

        String jwtToken = createGoogleIapToken(TEST_AUDIENCE);
        this.googleIapJwtVerifier.verifyJwt(jwtToken, TEST_AUDIENCE);
    }

}