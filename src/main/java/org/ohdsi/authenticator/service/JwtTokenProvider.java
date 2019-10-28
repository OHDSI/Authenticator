package org.ohdsi.authenticator.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.Getter;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.Optional;

@Component
public class JwtTokenProvider extends AbstractTokenProvider {

    @Value("${security.jwt.token.secretKey}")
    private String secretKey;

    @Value("${security.jwt.token.validityInSeconds}")
    @Getter
    private long validityInSeconds;

    @Override
    public String createToken(String username, Map<String, String> userAdditionalInfo, Date expirationDate) {

        Claims claims = Jwts.claims();
        claims
                .setSubject(username)
                .putAll(userAdditionalInfo);

        Date now = new Date();
        expirationDate = Optional.ofNullable(expirationDate).orElseGet(this::getDefaultExpDate);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(expirationDate)
                .signWith(getKey())
                .compact();
    }

    public Jws<Claims> validateAndResolveClaimsInner(String token) {
        try {
            return Jwts.parser().setSigningKey(getKey()).parseClaimsJws(token);
        } catch (Exception ex) {
            throw new AuthenticationException(INVALID_TOKEN_ERROR);
        }
    }

    private Key getKey() {
        return new SecretKeySpec(secretKey.getBytes(), SignatureAlgorithm.HS512.getJcaName());
    }

    private Date getDefaultExpDate() {

        Date now = new Date();
        return new Date(now.getTime() + (validityInSeconds * 1000));
    }
}
