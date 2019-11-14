package org.ohdsi.authenticator.service;

import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

@SpringBootTest
@RunWith(SpringRunner.class)
@ActiveProfiles(profiles = {"test-rest-proxy"})
public class RestAuthenticationWithProxyTest extends RestAuthenticationTest {

}
