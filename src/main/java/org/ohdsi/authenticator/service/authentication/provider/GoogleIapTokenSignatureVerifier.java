package org.ohdsi.authenticator.service.authentication.provider;

import com.google.common.base.Preconditions;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;
import java.net.URL;
import java.security.interfaces.ECPublicKey;
import java.util.HashMap;
import java.util.Map;

public class GoogleIapTokenSignatureVerifier {

    private static final String PUBLIC_KEY_VERIFICATION_URL = "https://www.gstatic.com/iap/verify/public_key-jwk";

    // using a simple cache with no eviction
    private final Map<String, JWK> keyCache = new HashMap<>();

    public boolean isSignatureValid(SignedJWT signedJwt, JWSHeader jwsHeader) throws Exception {
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
