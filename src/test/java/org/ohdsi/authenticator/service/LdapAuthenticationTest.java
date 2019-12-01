package org.ohdsi.authenticator.service;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.junit.Before;
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
@ActiveProfiles(profiles = {"test", "test-ldap"})
public class LdapAuthenticationTest extends BaseTest {

    private static final String METHOD = "ldap";

    private DirectoryTestOptions options;

    @Before
    public void before() {

        this.options = getOptions();
    }

    @Test
    public void testAuthSuccess() {

        UsernamePasswordCredentials credentials = options.getAcceptableCreds();
        UserInfo userInfo = authenticator.authenticate(options.getMethod(), credentials);
        assertThat(credentials.getUsername(),
                is(equalTo(userInfo.getUser().getUsername())));
        assertThat(options.getMethod(),
                equalTo(userInfo.getAuthenticationInfo().getAuthMethod()));
        assertThat(userInfo.getAuthenticationInfo().getToken(),
                notNullValue());
        assertThat(userInfo.getUser().getUsername(),
                equalTo(credentials.getUsername()));

        checkNormalUser(credentials, userInfo);
    }

    @Test
    public void testAuthFail() {

        UsernamePasswordCredentials credentials = options.getBadCreds();
        boolean isAuthenticated = true;
        try {
            authenticator.authenticate(options.getMethod(), credentials);
        } catch (AuthenticationException e) {
            isAuthenticated = false;
        }
        assertThat(isAuthenticated, is(equalTo(false)));
    }


    @Test
    public void testFindUser() {

        UsernamePasswordCredentials credentials = options.getAcceptableCreds();
        UserInfo userInfo = userService.findUser(options.getMethod(), credentials.getUsername()).orElse(null);
        assertThat(userInfo, notNullValue());

        checkNormalUser(credentials, userInfo);
    }


    @Test
    public void findAllUsers() {

        UsernamePasswordCredentials credentials = options.getAcceptableCreds();
        List<UserInfo> userInfos = userService.findAllUsers(options.getMethod());

        assertThat(userInfos.size(), equalTo(2));

        UserInfo userInfo = userInfos.stream()
                .filter(info -> StringUtils.equalsIgnoreCase(
                        options.getFirstName(),
                        info.getUser().getFirstname())
                )
                .findFirst().orElse(null);
        checkNormalUser(credentials, userInfo);
    }

    private void checkNormalUser(UsernamePasswordCredentials credentials, UserInfo userInfo) {
        assertThat(userInfo.getAdditionalInfo().get("firstName"),
                equalTo(options.getFirstName()));
        assertThat(userInfo.getAdditionalInfo().get("lastName"),
                equalTo(options.getLastName()));
    }

    protected DirectoryTestOptions getOptions() {

        return new DirectoryTestOptions() {
            @Override
            public UsernamePasswordCredentials getAcceptableCreds() {

                return new UsernamePasswordCredentials("user", "123");
            }

            @Override
            public UsernamePasswordCredentials getBadCreds() {

                return new UsernamePasswordCredentials("user", "badpassword");
            }

            @Override
            public String getFirstName() {

                return "John";
            }

            @Override
            public String getLastName() {

                return "Doe";
            }

            @Override
            public String getMethod() {

                return METHOD;
            }
        };
    }

    interface DirectoryTestOptions {

        UsernamePasswordCredentials getAcceptableCreds();

        UsernamePasswordCredentials getBadCreds();

        String getFirstName();

        String getLastName();

        String getMethod();
    }

}
