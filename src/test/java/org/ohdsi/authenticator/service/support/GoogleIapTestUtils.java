package org.ohdsi.authenticator.service.support;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.time.LocalDateTime;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;

public class GoogleIapTestUtils {

    public static String createGoogleIapToken(String audience) {
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary("SECRET_KEY_FOR_SIGN_SECRET_KEY_FOR_SIGN_SECRET_KEY_FOR_SIGN_SECRET_KEY_FOR_SIGN_SECRET_KEY_FOR_SIGN_SECRET_KEY_FOR_SIGN");
        Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());


        Claims claims = createClaims(audience);

        return Jwts.builder()
                .setHeaderParam("kid", "mpf0DA")
                .setClaims(claims)
                .signWith(signingKey, signatureAlgorithm)
                .compact();
    }

    public static Claims createClaims(String audience) {
        Claims claims = Jwts.claims();
        claims.setSubject("loginFromSubject@gmail.com");
        claims.setExpiration(toDate(LocalDateTime.now().plusYears(1)));
        claims.setAudience(audience);
        claims.setIssuedAt(toDate(LocalDateTime.now().minusYears(1)));
        claims.setIssuer("https://cloud.google.com/iap");
        claims.put("email", "login@gmail.com");
        return claims;
    }

    private static Date toDate(LocalDateTime localDateTime) {
        return Date.from(localDateTime.atZone(ZoneId.systemDefault())
                        .toInstant());
    }

}
