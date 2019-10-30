package org.ohdsi.authenticator.service.support;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;

public class GoogleIapUtils {

    public static String createJwtToken() {
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary("SECRET_KEY_FOR_SIGN_SECRET_KEY_FOR_SIGN_SECRET_KEY_FOR_SIGN_SECRET_KEY_FOR_SIGN_SECRET_KEY_FOR_SIGN_SECRET_KEY_FOR_SIGN");
        Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());


        Claims claims = createClaims();

        return Jwts.builder()
                .setHeaderParam("kid", "mpf0DA")
                .setClaims(claims)
                .signWith(signingKey, signatureAlgorithm)
                .compact();
    }

    public static Claims createClaims() {
        Claims claims = Jwts.claims();
        claims.setSubject("loginFromSubject@gmail.com");
        claims.setExpiration(toDate(LocalDate.now().plusYears(1)));
        claims.setAudience("testAudience");
        claims.setIssuedAt(toDate(LocalDate.now().minusYears(1)));
        claims.setIssuer("https://cloud.google.com/iap");
        claims.put("email", "login@gmail.com");
        return claims;
    }

    private static Date toDate(LocalDate localDate) {
        return Date.from(localDate.atStartOfDay(ZoneId.systemDefault()).toInstant());
    }

}
