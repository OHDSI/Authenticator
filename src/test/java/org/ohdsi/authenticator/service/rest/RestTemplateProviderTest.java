package org.ohdsi.authenticator.service.rest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;

import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.ohdsi.authenticator.service.proxy.ProxyInitializer;
import org.ohdsi.authenticator.service.rest.config.ProxyConfig;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

@RunWith(MockitoJUnitRunner.class)
public class RestTemplateProviderTest {

    public static final String TEST_URL = "https://www.arachnenetwork.com/api/v1/build-number";
    public static final String PROXY_URL = "localhost";
    public static final int PROXY_PORT = 9990;

    @ClassRule
    public static final TestRule serviceInitializer = ProxyInitializer.INSTANCE;

    @Test
    public void createRestTemplate_createTemplateNoProxy() {

        RestTemplateProvider restTemplateProvider = new RestTemplateProvider(
                ProxyConfig.builder()
                        .enabled(false)
                        .build()
        );

        RestTemplate restTemplate = restTemplateProvider.createRestTemplate();
        ResponseEntity<String> response = restTemplate.exchange(TEST_URL, HttpMethod.GET, null, String.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getBody().contains("buildNumber"));
        assertTrue(response.getBody().contains("buildId"));
        assertTrue(response.getBody().contains("projectVersion"));
    }

    @Test
    public void createRestTemplate_createTemplateWithProxy() {

        RestTemplateProvider restTemplateProvider = new RestTemplateProvider(
                ProxyConfig.builder()
                        .enabled(true)
                        .host(PROXY_URL)
                        .port(PROXY_PORT)
                        .authEnabled(false)
                        .build()
        );

        RestTemplate restTemplate = restTemplateProvider.createRestTemplate();

        // httpProxySpy is shared among all unit tests so it is possible that `handleRequest` method was already invoked,
        // to avoid this we reset our spy
        Mockito.reset(ProxyInitializer.httpProxySpy);
        ResponseEntity<String> response = restTemplate.exchange(TEST_URL, HttpMethod.GET, null, String.class);

        verify(ProxyInitializer.httpProxySpy).handleRequest(any());
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getBody().contains("buildNumber"));
        assertTrue(response.getBody().contains("buildId"));
        assertTrue(response.getBody().contains("projectVersion"));
    }
}