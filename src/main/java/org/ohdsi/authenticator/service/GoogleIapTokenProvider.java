package org.ohdsi.authenticator.service;

import com.nimbusds.jwt.JWTClaimsSet;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.util.Date;
import java.util.Map;

@Component
public class GoogleIapTokenProvider extends AbstractInvalidatableTokenProvider {

    public static final String AUDIENCE_FORMAT = "/projects/%s/global/backendServices/%s";

    private GoogleIapJwtVerifier googleIapJwtVerifier;
    private boolean googleIapEnabled;
    private Long cloudProjectId;
    private Long backendServiceId;

    public GoogleIapTokenProvider(GoogleIapJwtVerifier googleIapJwtVerifier,
                                  @Value("${security.googleIap.enabled:false}") boolean googleIapEnabled,
                                  @Value("${security.googleIap.cloudProjectId:}") Long cloudProjectId,
                                  @Value("${security.googleIap.backendServiceId:}") Long backendServiceId) {
        this.googleIapJwtVerifier = googleIapJwtVerifier;
        this.googleIapEnabled = googleIapEnabled;
        this.cloudProjectId = cloudProjectId;
        this.backendServiceId = backendServiceId;
    }

    @PostConstruct
    private void init() {
        if (googleIapEnabled && cloudProjectId == null && backendServiceId == null) {
            if (cloudProjectId == null) {
                throw new IllegalStateException("IAP properties configured wrong: cloudProjectId is empty");
            }
            if (backendServiceId == null) {
                throw new IllegalStateException("IAP properties configured wrong: backendServiceId is empty");
            }
        }
    }

    @Override
    public AccessToken createToken(String username, Map<String, String> userAdditionalInfo, Date expirationDate) {

        if (!googleIapEnabled) {
            throw new IllegalStateException("IAP properties configured wrong");
        }
        throw new IllegalStateException();
    }

    @Override
    protected Claims validateAndResolveClaimsInternal(AccessToken token) {
        if (!googleIapEnabled) {
            throw new AuthenticationException("IAP properties configured wrong");
        }
        String audience = String.format(AUDIENCE_FORMAT, Long.toUnsignedString(cloudProjectId), Long.toUnsignedString(backendServiceId));
        JWTClaimsSet jwtClaimsSet = googleIapJwtVerifier.verifyJwt(token.getValue(), audience);

        return convertToClaims(audience, jwtClaimsSet);

    }

    // To validate IAP token we use different jwt library, so we need to convert from JwtClaimsSet to Claims
    // The reason why I decided to keep two JWT library in on project is that all examples of official documentation are written using nimbusds library,
    // and this library has a good support for retrieving public signature keys from remote repositories. On the other hand we use jsonwebtoken all over other application.
    private Claims convertToClaims(String audience, JWTClaimsSet jwtClaimsSet) {
        Claims claims = Jwts.claims();
        claims.putAll(jwtClaimsSet.getClaims());
        claims.setAudience(audience);
        Object userEmail = jwtClaimsSet.getClaim(GoogleIapJwtVerifier.USER_EMAIL_FIELD);
        if (userEmail != null) {
            claims.setSubject(userEmail.toString());
        }
        return claims;
    }
}
