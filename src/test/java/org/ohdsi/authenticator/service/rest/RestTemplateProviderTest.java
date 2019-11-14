package org.ohdsi.authenticator.service.rest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.ohdsi.authenticator.service.rest.config.ProxyConfig;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

public class RestTemplateProviderTest {

    public static final String TEST_URL = "https://www.arachnenetwork.com/api/v1/build-number";
    //this proxy ip is not fixed, so it could change. To fix this use any available proxy
    public static final String PROXY_URL = "167.99.232.18";
    public static final int PROXY_PORT = 8080;

    @Test
    public void createRestTemplate_createTemplateNoProxy() throws Exception {

        RestTemplateProvider restTemplateProvider = new RestTemplateProvider(
                ProxyConfig.builder()
                        .enabled(false)
                        .build()
        );

        RestTemplate restTemplate = restTemplateProvider.createRestTemplate();
        ResponseEntity<String> response = restTemplate.exchange(TEST_URL, HttpMethod.GET, null, String.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());
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
        ResponseEntity<String> response = restTemplate.exchange(TEST_URL, HttpMethod.GET, null, String.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(response.getBody().contains("buildNumber"));
        assertTrue(response.getBody().contains("buildId"));
        assertTrue(response.getBody().contains("projectVersion"));
    }
}