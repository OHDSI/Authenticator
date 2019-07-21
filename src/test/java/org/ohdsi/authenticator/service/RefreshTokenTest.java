package org.ohdsi.authenticator.service;

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

        String token = createDummyToken("db");
        Assert.isTrue(getExpirationInSecs(token) <= DUMMY_EXP_IN_SEC, "Wrong dummy token");
        String newToken = authenticator.refreshToken(token).getToken();
        long newExpInSecs = getExpirationInSecs(newToken);
        Assert.isTrue(
            newExpInSecs >= DUMMY_EXP_IN_SEC && newExpInSecs <= jwtTokenProvider.getDefaultValidityInSeconds()
            && Objects.equals(jwtTokenProvider.resolveClaims(newToken).getBody().get(DUMMY_PROP_KEY), DUMMY_PROP_VAL),
            "Token hasn't been refreshed"
        );
    }

    @Test
    public void testRestTokenRefresh() throws InterruptedException {

        final var method = "rest-arachne";
        var authRequest = new UsernamePasswordCredentials(arachneUsername, arachnePassword);
        UserInfo userInfo = authenticator.authenticate(method, authRequest);

        String token = userInfo.getToken();
        Date originalExpDate = jwtTokenProvider.getExpDate(token);

        Thread.sleep(1000L);

        String newToken = authenticator.refreshToken(token).getToken();
        Date newExpDate = jwtTokenProvider.getExpDate(newToken);
        long newExpInSecs = getExpirationInSecs(newToken);

        Assert.isTrue(
            newExpInSecs > jwtTokenProvider.getDefaultValidityInSeconds()
            && originalExpDate.before(newExpDate),
            "Token hasn't been refreshed"
        );
    }

    private String createDummyToken(String forMethod) {

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
