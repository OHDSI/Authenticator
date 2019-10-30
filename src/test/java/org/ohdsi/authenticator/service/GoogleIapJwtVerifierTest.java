package org.ohdsi.authenticator.service;

import com.nimbusds.jwt.JWTClaimsSet;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Spy;
import org.mockito.junit.MockitoJUnitRunner;
import org.ohdsi.authenticator.exception.AuthenticationException;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.ohdsi.authenticator.service.support.GoogleIapUtils.createJwtToken;

@RunWith(MockitoJUnitRunner.class)
public class GoogleIapJwtVerifierTest {

    @Spy
    private GoogleIapJwtVerifier googleIapJwtVerifier;

    @Test
    public void verifyJwt_validSignature() throws Exception {
        doReturn(true)
                .when(this.googleIapJwtVerifier)
                .isSignatureValid(any(), any());
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

        String jwtToken = createJwtToken();
        JWTClaimsSet claims = this.googleIapJwtVerifier.verifyJwt(jwtToken, "testAudience");
        String login = claims.getClaim(GoogleIapJwtVerifier.USER_EMAIL_FIELD).toString();
        assertEquals("login@gmail.com", login);
    }

    @Test(expected = AuthenticationException.class)
    public void verifyJwt_InvalidSignature() throws Exception {
        doReturn(false)
                .when(this.googleIapJwtVerifier)
                .isSignatureValid(any(), any());

        String jwtToken = createJwtToken();
        this.googleIapJwtVerifier.verifyJwt(jwtToken, "testAudience");
    }

}