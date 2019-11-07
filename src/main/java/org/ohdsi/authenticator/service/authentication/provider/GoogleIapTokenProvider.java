package org.ohdsi.authenticator.service.authentication.provider;

import com.nimbusds.jwt.JWTClaimsSet;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import java.util.Date;
import java.util.Map;
import javax.annotation.PostConstruct;

public class GoogleIapTokenProvider extends AbstractInvalidatableTokenProvider {

    public static final String AUDIENCE_FORMAT = "/projects/%s/global/backendServices/%s";

    private GoogleIapTokenVerifier googleIapTokenVerifier;
    private Long cloudProjectId;
    private Long backendServiceId;

    public GoogleIapTokenProvider(GoogleIapTokenVerifier googleIapTokenVerifier,
                                  Long cloudProjectId,
                                  Long backendServiceId) {

        this.googleIapTokenVerifier = googleIapTokenVerifier;
        this.cloudProjectId = cloudProjectId;
        this.backendServiceId = backendServiceId;
    }

    @PostConstruct
    private void init() {

        if (cloudProjectId == null) {
            throw new IllegalStateException("IAP properties configured wrong: cloudProjectId is empty");
        }
        if (backendServiceId == null) {
            throw new IllegalStateException("IAP properties configured wrong: backendServiceId is empty");
        }
    }

    @Override
    public String createToken(String username, Map<String, String> userAdditionalInfo, Date expirationDate) {

        throw new IllegalStateException("IAP token cannot be generated. This is responsibility of GCP");
    }

    @Override
    public Claims validateTokenAndGetClaims(String token) {

        checkThatTokenWasNotInvalidated(token);

        String audience = String.format(AUDIENCE_FORMAT, Long.toUnsignedString(cloudProjectId), Long.toUnsignedString(backendServiceId));
        JWTClaimsSet jwtClaimsSet = googleIapTokenVerifier.verifyTokenAndGetClaim(token, audience);

        return convertToClaims(audience, jwtClaimsSet);

    }

    // To validate IAP token we use different jwt library, so we need to convert from JwtClaimsSet to Claims
    // The reason why I decided to keep two JWT library in the project is that all examples of official documentation are written using nimbusds library,
    // and this library has a good support for retrieving public signature keys from remote repositories. On the other hand we use jsonwebtoken all over other application.
    private Claims convertToClaims(String audience, JWTClaimsSet jwtClaimsSet) {

        Claims claims = Jwts.claims();
        claims.putAll(jwtClaimsSet.getClaims());
        claims.setAudience(audience);
        Object userEmail = jwtClaimsSet.getClaim(GoogleIapTokenVerifier.USER_EMAIL_FIELD);
        if (userEmail != null) {
            claims.setSubject(userEmail.toString());
        }
        return claims;
    }

}
