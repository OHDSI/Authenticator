package org.ohdsi.authenticator.service;

import static org.junit.Assert.assertEquals;

import org.junit.Assert;
import org.junit.Test;
import org.ohdsi.authenticator.service.authentication.AuthenticationMode;
import org.ohdsi.authenticator.service.authentication.AccessTokenResolver;

public class AccessTokenResolverTest {

    @Test
    public void getTokenHeaderName_standardAuthenticationMode() {
        AccessTokenResolver accessTokenResolver = new AccessTokenResolver("jwt-header", AuthenticationMode.STANDARD);
        assertEquals("jwt-header", accessTokenResolver.getTokenHeaderName());
    }


    @Test
    public void getTokenHeaderName_proxyAuthenticationMode() {
        AccessTokenResolver accessTokenResolver = new AccessTokenResolver("jwt-header", AuthenticationMode.PROXY);
        assertEquals(AccessTokenResolver.GOOGLE_IAP_JWT_HEADER, accessTokenResolver.getTokenHeaderName());
    }
}