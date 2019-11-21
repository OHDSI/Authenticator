package org.ohdsi.authenticator.service.proxy;

import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.rules.ExternalResource;
import org.junit.rules.TestRule;


/**
 * Proxy should be start only ONCE for all unit tests!!
 */
public class ProxyInitializer extends ExternalResource {

    public static TestHttpProxy server = new TestHttpProxy();

    public static final TestRule INSTANCE = new ProxyInitializer();
    private AtomicBoolean started = new AtomicBoolean();

    @Override
    protected void before() throws Throwable {
        if (!started.compareAndSet(false, true)) {
            return;
        }
        this.startProxy();
    }

    private void startProxy() {
        server.start();
    }
}
