package org.ohdsi.authenticator.service.rest;

import lombok.AllArgsConstructor;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.HttpClientBuilder;
import org.ohdsi.authenticator.service.rest.config.ProxyConfig;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;


@AllArgsConstructor
public class RestTemplateProvider {

    private ProxyConfig config;

    public RestTemplate createRestTemplate() {

        if (config == null || !config.isEnabled()) {
            return new RestTemplate();
        }
        HttpClient httpClient = HttpClientBuilder
                .create()
                .setProxy(new HttpHost(config.getHost(), config.getPort()))
                .setDefaultCredentialsProvider(createCredentialsProvider())
                .disableCookieManagement()
                .build();

        HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory();
        factory.setHttpClient(httpClient);

        return new RestTemplate(factory);
    }

    private CredentialsProvider createCredentialsProvider() {

        if (!config.isAuthEnabled() || StringUtils.isEmpty(config.getUsername())) {
            return null;
        }
        CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
        credentialsProvider.setCredentials(
                new AuthScope(config.getHost(), config.getPort()),
                new UsernamePasswordCredentials(config.getUsername(), config.getPassword()));
        return credentialsProvider;
    }

}
