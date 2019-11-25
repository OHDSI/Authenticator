package org.ohdsi.authenticator.service;

import org.junit.ClassRule;
import org.junit.rules.TestRule;
import org.junit.runner.RunWith;
import org.ohdsi.authenticator.service.proxy.ProxyInitializer;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

@SpringBootTest
@RunWith(SpringRunner.class)
@ActiveProfiles(profiles = {"test-rest-proxy"})
public class RestAuthenticationWithProxyTest extends RestAuthenticationTest {

    @ClassRule
    public static final TestRule serviceInitializer = ProxyInitializer.INSTANCE;

}
