package org.ohdsi.authenticator.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Date;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@Component
public class JwtTokenProvider {

    private static final String INVALID_TOKEN_ERROR = "Expired or invalid JWT token";

    private Set<String> invalidatedTokens = new HashSet<>();

    @Value("${security.jwt.token.secretKey}")
    private String secretKey;

    @Value("${security.jwt.token.validityInSeconds}")
    private long validityInSeconds;

    public String createToken(String username, Map<String, String> userAdditionalInfo) {

        return createToken(username, userAdditionalInfo, null);
    }

    public String createToken(String username, Map<String, String> userAdditionalInfo, Date expirationDate) {

        Claims claims = Jwts.claims().setSubject(username);
        claims.putAll(userAdditionalInfo);

        Date now = new Date();
        expirationDate = Optional.ofNullable(expirationDate).orElseGet(this::getDefaultExpDate);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(expirationDate)
                .signWith(getKey())
                .compact();
    }

    void invalidateToken(String token) {

        invalidatedTokens.add(token);
    }

    Jws<Claims> resolveClaims(String token) {

        if (invalidatedTokens.contains(token)) {
            throw new AuthenticationException(INVALID_TOKEN_ERROR);
        }

        try {
            Jws<Claims> claims = Jwts.parser().setSigningKey(getKey()).parseClaimsJws(token);
            return claims;
        } catch (Exception ex) {
            throw new AuthenticationException(INVALID_TOKEN_ERROR);
        }
    }

    long getDefaultValidityInSeconds() {

        return validityInSeconds;
    }

    Date getExpDate(String token) {

        return resolveClaims(token).getBody().getExpiration();
    }

    private Key getKey() {

        return new SecretKeySpec(secretKey.getBytes(), SignatureAlgorithm.HS512.getJcaName());
    }

    private Date getDefaultExpDate() {

        Date now = new Date();
        return new Date(now.getTime() + (validityInSeconds * 1000));
    }
}
