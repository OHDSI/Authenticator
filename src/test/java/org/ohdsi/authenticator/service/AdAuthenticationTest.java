package org.ohdsi.authenticator.service;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.ohdsi.authenticator.model.UserInfo;
import org.pac4j.core.credentials.UsernamePasswordCredentials;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

@SpringBootTest
@RunWith(SpringRunner.class)
@ActiveProfiles(profiles = "test")
public class AdAuthenticationTest extends LdapAuthenticationTest {

    private final static String METHOD = "ad";

    @Value("${authenticator.methods.ad.config.userDn}")
    private String userDn;
    @Value("${authenticator.methods.ad.config.password}")
    private String password;

    @Override
    protected DirectoryTestOptions getOptions() {
        return new DirectoryTestOptions() {
            @Override
            public UsernamePasswordCredentials getAcceptableCreds() {
                return new UsernamePasswordCredentials(userDn, password);
            }

            @Override
            public UsernamePasswordCredentials getBadCreds() {
                return new UsernamePasswordCredentials(userDn, "badpassword");
            }

            @Override
            public String getFirstName() {
                return "John";
            }

            @Override
            public String getLastName() {
                return "Smith";
            }

            @Override
            public String getMethod() {
                return METHOD;
            }
        };
    }
}
