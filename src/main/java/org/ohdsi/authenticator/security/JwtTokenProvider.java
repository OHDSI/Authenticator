package org.ohdsi.authenticator.security;

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
import java.util.Map;

@Component
public class JwtTokenProvider {

    @Value("${security.jwt.token.secretKey}")
    private String secretKey;

    @Value("${security.jwt.token.validityInSeconds}")
    private long validityInSeconds;

    public String createToken(String username, Map<String, String> userAdditionalInfo) {

        Claims claims = Jwts.claims().setSubject(username);
        claims.putAll(userAdditionalInfo);

        Date now = new Date();
        Date validity = new Date(now.getTime() + (validityInSeconds * 1000));

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(getKey())
                .compact();
    }

    public Jws<Claims> resolveClaims(String token) {

        try {
            Jws<Claims> claims = Jwts.parser().setSigningKey(getKey()).parseClaimsJws(token);
            return claims;
        } catch (Exception ex) {
            throw new AuthenticationException("Expired or invalid JWT token");
        }
    }

    private Key getKey() {

        return new SecretKeySpec(secretKey.getBytes(), SignatureAlgorithm.HS256.getJcaName());
    }
}
