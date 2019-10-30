package org.ohdsi.authenticator.service;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.ohdsi.authenticator.model.UserInfo;
import org.ohdsi.authenticator.service.support.GoogleIapUtils;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class TokenServiceImplTest {

    private TokenService tokenService;

    @Mock
    private GoogleIapTokenProvider googleIapTokenProvider;

    @Before
    public void setUp() throws Exception {
        tokenService = Mockito.spy(new TokenServiceImpl(googleIapTokenProvider));
        when(googleIapTokenProvider.validateTokenAndGetClaims(any())).thenReturn(GoogleIapUtils.createClaims());
    }

    @Test
    public void name() {
        String tokenString = "somevalue";
        UserInfo userInfo = tokenService.resolveUser(AccessToken.iap(tokenString));
        assertEquals("loginFromSubject@gmail.com", userInfo.getUsername());
        assertEquals("loginFromSubject@gmail.com", userInfo.getUsername());
        assertEquals(tokenString, userInfo.getToken());
        assertEquals("testAudience", userInfo.getAdditionalInfo().get("aud"));

    }
}