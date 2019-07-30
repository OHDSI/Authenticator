package org.ohdsi.authenticator.service;

import org.junit.runner.RunWith;
import org.pac4j.core.credentials.UsernamePasswordCredentials;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

@SpringBootTest
@RunWith(SpringRunner.class)
@ActiveProfiles(profiles = { "test", "testad" })
public class AdAuthenticationTest extends LdapAuthenticationTest {

    private final static String METHOD = "ad";

    private String USER_DN = "user";
    private String PASSWORD = "123";

    @Override
    protected DirectoryTestOptions getOptions() {
        return new DirectoryTestOptions() {
            @Override
            public UsernamePasswordCredentials getAcceptableCreds() {
                return new UsernamePasswordCredentials(USER_DN, PASSWORD);
            }

            @Override
            public UsernamePasswordCredentials getBadCreds() {
                return new UsernamePasswordCredentials(USER_DN, "badpassword");
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
}
