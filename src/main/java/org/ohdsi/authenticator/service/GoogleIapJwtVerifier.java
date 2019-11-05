package org.ohdsi.authenticator.service;

import com.google.common.base.Preconditions;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.net.URL;
import java.security.interfaces.ECPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.springframework.stereotype.Component;

@Component

public class GoogleIapJwtVerifier {

    private static final String PUBLIC_KEY_VERIFICATION_URL = "https://www.gstatic.com/iap/verify/public_key-jwk";
    private static final String IAP_ISSUER_URL = "https://cloud.google.com/iap";
    public static final String USER_EMAIL_FIELD = "email";

    // using a simple cache with no eviction
    private final Map<String, JWK> keyCache = new HashMap<>();

    private static Clock clock = Clock.systemUTC();

    public JWTClaimsSet verifyJwt(String jwtToken, String expectedAudience) {

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

            if (isSignatureValid(signedJwt, jwsHeader)) {
                return claims;
            }
            throw new AuthenticationException("Jwt token is not valid.");
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new AuthenticationException(ex);
        }
    }

    protected boolean isSignatureValid(SignedJWT signedJwt, JWSHeader jwsHeader) throws Exception {
        // verify using public key : lookup with key id, algorithm name provided
        ECPublicKey publicKey = getAndCacheKey(jwsHeader.getKeyID(), jwsHeader.getAlgorithm().getName());

        Preconditions.checkNotNull(publicKey);
        JWSVerifier jwsVerifier = new ECDSAVerifier(publicKey);

        return signedJwt.verify(jwsVerifier);
    }

    private ECPublicKey getAndCacheKey(String kid, String alg) throws Exception {

        JWK jwk = keyCache.get(kid);
        if (jwk == null) {
            // update cache loading jwk public key data from url
            JWKSet jwkSet = JWKSet.load(new URL(PUBLIC_KEY_VERIFICATION_URL));
            for (JWK key : jwkSet.getKeys()) {
                keyCache.put(key.getKeyID(), key);
            }
            jwk = keyCache.get(kid);
        }
        // confirm that algorithm matches
        if (jwk != null && jwk.getAlgorithm().getName().equals(alg)) {
            return ECKey.parse(jwk.toJSONString()).toECPublicKey();
        }
        return null;
    }

}
