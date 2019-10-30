package org.ohdsi.authenticator.service;

import lombok.var;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ohdsi.authenticator.model.UserInfo;
import org.pac4j.core.credentials.UsernamePasswordCredentials;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.Assert;

import java.util.Date;
import java.util.HashMap;
import java.util.Objects;

@SpringBootTest
@RunWith(SpringRunner.class)
@ActiveProfiles(profiles = "test")
public class RefreshTokenTest extends BaseTest {

    private static final Integer DUMMY_EXP_IN_SEC = 15;
    private static final String METHOD_PROP_KEY = "method";
    private static final String DUMMY_PROP_KEY = "test";
    private static final String DUMMY_PROP_VAL = "abc";

    @Value("${credentials.rest-arachne.username}")
    private String arachneUsername;
    @Value("${credentials.rest-arachne.password}")
    private String arachnePassword;

    @Test
    public void testDefaultTokenRefresh() {

        AccessToken token = createDummyToken("db");
        Assert.isTrue(getExpirationInSecs(token) <= DUMMY_EXP_IN_SEC, "Wrong dummy token");
        AccessToken newToken = AccessToken.jwt(authenticator.refreshToken(token).getToken());

        long newExpInSecs = getExpirationInSecs(newToken);
        Assert.isTrue(
            newExpInSecs >= DUMMY_EXP_IN_SEC && newExpInSecs <= jwtTokenProvider.getValidityInSeconds()
            && Objects.equals(jwtTokenProvider.validateTokenAndGetClaims(newToken).get(DUMMY_PROP_KEY), DUMMY_PROP_VAL),
            "Token hasn't been refreshed"
        );
    }

    @Test
    public void testRestTokenRefresh() throws InterruptedException {

        final var method = "rest-arachne";
        UsernamePasswordCredentials authRequest = new UsernamePasswordCredentials(arachneUsername, arachnePassword);
        UserInfo userInfo = authenticator.authenticate(method, authRequest);

        AccessToken token = AccessToken.jwt(userInfo.getToken());

        Date originalExpDate = jwtTokenProvider.validateTokenAndGetClaims(token).getExpiration();

        Thread.sleep(1000L);

        AccessToken newToken =  AccessToken.jwt(authenticator.refreshToken(token).getToken());

        Date newExpDate = jwtTokenProvider.validateTokenAndGetClaims(newToken).getExpiration();
        long newExpInSecs = getExpirationInSecs(newToken);

        Assert.isTrue(
            newExpInSecs > jwtTokenProvider.getValidityInSeconds()
            && originalExpDate.before(newExpDate),
            "Token hasn't been refreshed"
        );
    }

    private AccessToken createDummyToken(String forMethod) {

        return jwtTokenProvider.createToken(
            "dummy",
            new HashMap<String, String>() {{
                put(METHOD_PROP_KEY, forMethod);
                put(DUMMY_PROP_KEY, DUMMY_PROP_VAL);
            }},
            new Date(new Date().getTime() + DUMMY_EXP_IN_SEC * 1000)
        );
    }
}
