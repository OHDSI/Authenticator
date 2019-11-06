package org.ohdsi.authenticator.service.authentication.provider;

import com.google.common.base.Preconditions;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import org.ohdsi.authenticator.exception.AuthenticationException;

public class GoogleIapTokenVerifier {

    private static final String IAP_ISSUER_URL = "https://cloud.google.com/iap";
    public static final String USER_EMAIL_FIELD = "email";

    private GoogleIapTokenSignatureVerifier googleIapTokenSignatureVerifier;

    private static Clock clock = Clock.systemUTC();

    public GoogleIapTokenVerifier(GoogleIapTokenSignatureVerifier googleIapTokenSignatureVerifier) {

        this.googleIapTokenSignatureVerifier = googleIapTokenSignatureVerifier;
    }

    public JWTClaimsSet verifyTokenAndGetClaim(String jwtToken, String expectedAudience) {

        try {
            // parse signed token into header / claims
            SignedJWT signedJwt = SignedJWT.parse(jwtToken);
            JWSHeader jwsHeader = signedJwt.getHeader();

            // header must have algorithm("alg") and "kid"
            Preconditions.checkNotNull(jwsHeader.getAlgorithm());
            Preconditions.checkNotNull(jwsHeader.getKeyID());

            JWTClaimsSet claims = signedJwt.getJWTClaimsSet();

            // claims must have audience, issuer
            Preconditions.checkArgument(claims.getAudience().contains(expectedAudience));
            Preconditions.checkArgument(claims.getIssuer().equals(IAP_ISSUER_URL));

            // claim must have issued at time in the past
            Date currentTime = Date.from(Instant.now(clock));
            Preconditions.checkArgument(claims.getIssueTime().before(currentTime));
            // claim must have expiration time in the future
            Preconditions.checkArgument(claims.getExpirationTime().after(currentTime));

            // must have subject, email
            String email = claims.getClaim("email").toString();
            Preconditions.checkNotNull(email);
            Preconditions.checkNotNull(claims.getSubject());

            if (googleIapTokenSignatureVerifier.isSignatureValid(signedJwt, jwsHeader)) {
                return claims;
            }
            throw new AuthenticationException("Jwt token is not valid.");
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new AuthenticationException(ex);
        }
    }


}
