package org.ohdsi.authenticator.service;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.ohdsi.authenticator.model.UserInfo;
import org.pac4j.core.credentials.UsernamePasswordCredentials;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

@SpringBootTest
@RunWith(SpringRunner.class)
@ActiveProfiles(profiles = "test")
public class LdapAuthenticationTest extends BaseTest {

    private static final String METHOD = "ldap";

    @Test
    public void testAuthSuccess() {

        UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("user", "123");
        UserInfo userInfo = authenticator.authenticate(METHOD, credentials);
        assertThat(credentials.getUsername(), is(equalTo(userInfo.getUsername())));
        assertThat(METHOD, is(equalTo(userInfo.getAuthMethod())));
        assertThat(userInfo.getToken(), is(notNullValue()));
        assertThat(userInfo.getAdditionalInfo().get("firstName"), is(equalTo("John")));
        assertThat(userInfo.getAdditionalInfo().get("lastName"), is(equalTo("Doe")));
    }

    @Test
    public void testAuthFail() {

        UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("user", "badpassword");
        boolean isAuthenticated = true;
        try {
            authenticator.authenticate(METHOD, credentials);
        } catch (AuthenticationException e) {
            isAuthenticated = false;
        }
        assertThat(isAuthenticated, is(equalTo(false)));
    }

}
