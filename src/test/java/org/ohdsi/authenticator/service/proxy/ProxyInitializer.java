package org.ohdsi.authenticator.service.proxy;

import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.rules.ExternalResource;
import org.junit.rules.TestRule;
import org.mockito.Mockito;


/**
 * The proxy should be started only ONCE for all unit tests!!
 */
public class ProxyInitializer extends ExternalResource {

    public static TestHttpProxy httpProxySpy = Mockito.spy(new TestHttpProxy());

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
        httpProxySpy.start();
    }
}
