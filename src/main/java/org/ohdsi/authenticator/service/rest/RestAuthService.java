package org.ohdsi.authenticator.service.rest;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import lombok.var;
import org.apache.logging.log4j.util.Strings;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.ohdsi.authenticator.model.AuthenticationRequest;
import org.ohdsi.authenticator.service.AuthService;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;

public class RestAuthService extends AuthService<RestAuthServiceConfig> {

    public RestAuthService(RestAuthServiceConfig config) {

        super(config);
    }

    @Override
    public Authentication authenticate(AuthenticationRequest request) {

        RestTemplate restTemplate = new RestTemplate();

        HttpHeaders headers = getAuthHeaders();
        Map<String, String> body = getAuthBody(request);

        HttpEntity httpEntity = new HttpEntity(formatBody(body, headers.getContentType()), headers);
        ResponseEntity<String> responseEntity = restTemplate.exchange(config.getUrl(), HttpMethod.POST, httpEntity, String.class);

        var isAuthenticated = isSuccessfulLogin(responseEntity);
        var authBuilder = new AuthenticationBuilder()
            .setAuthenticated(isAuthenticated)
            .setUsername(request.getUsername());

        if (isAuthenticated) {
            var details = Stream.of(responseEntity)
                .map(this::extractToken)
                .map(this::queryUserInfo)
                .map(this::extractUserInfo)
                .findFirst().orElseThrow(() -> new AuthenticationException(INFO_EXTRACTION_ERROR));
            authBuilder.setUserDetails(details);
        }

        return authBuilder.build();
    }

    private HttpHeaders getAuthHeaders() {

        HttpHeaders headers = new HttpHeaders();

        switch (config.getBodyFormat()) {
            case FORMDATA:
                headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
                break;
            case JSON:
                headers.setContentType(MediaType.APPLICATION_JSON_UTF8);
                break;
        }

        return headers;
    }

    private Map<String, String> getAuthBody(AuthenticationRequest request) {

        ExpressionParser parser = new SpelExpressionParser();
        StandardEvaluationContext context = new StandardEvaluationContext(request);

        Map<String, String> body = new HashMap<>();
        config.getParams().forEach((k, e) -> {
            String val = parser.parseExpression(e).getValue(context, String.class);
            body.put(k, val);
        });

        return body;
    }

    private Map formatBody(Map<String, String> rawBody, MediaType mediaType) {

        if (Objects.equals(mediaType, MediaType.APPLICATION_FORM_URLENCODED)) {
            // FormData type requires MultiValueMap otherwise fails with no converter exception
            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            rawBody.forEach(body::add);
            return body;
        } else {
            return rawBody;
        }
    }

    private boolean isSuccessfulLogin(ResponseEntity<String> responseEntity) {

        boolean success = true;

        HttpStatus statusCriterion = config.getLoginSuccessCriteria().getStatus();
        if (Objects.nonNull(statusCriterion)) {
            success = success && Objects.equals(responseEntity.getStatusCode(), statusCriterion);
        }

        Map<String, String> bodyCriteria = config.getLoginSuccessCriteria().getBodyProperty();
        for (String path : bodyCriteria.keySet()) {
            String requiredVal = bodyCriteria.get(path);
            String actualVal = JsonPath.parse(responseEntity.getBody()).read(path, String.class);
            success = success && (Strings.isNotBlank(requiredVal) ? Objects.equals(requiredVal, actualVal) : Objects.nonNull(actualVal));
        }

        return success;
    }

    private String extractToken(ResponseEntity<String> responseEntity) {

        RestAuthServiceConfig.TokenConfig tokenConfig = config.getToken();
        String token = null;

        if (Objects.equals(tokenConfig.getSource(), RestAuthServiceConfig.HttpPart.HEADERS)) {
            token = responseEntity.getHeaders().getFirst(tokenConfig.getKey());
        } else if (Objects.equals(tokenConfig.getSource(), RestAuthServiceConfig.HttpPart.BODY)) {
            token = JsonPath.parse(responseEntity.getBody()).read(tokenConfig.getKey());
        }

        return token;
    }

    private ResponseEntity<String> queryUserInfo(String token) {

        RestTemplate restTemplate = new RestTemplate();

        MultiValueMap<String, String> headers = new LinkedMultiValueMap<String, String>() {{
            add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
            add(config.getToken().getTargetHeader(), String.format(config.getToken().getTargetFormat(), token));
        }};

        Map<String, String> body = new HashMap<>();

        HttpEntity httpEntity = new HttpEntity(body, headers);

        return restTemplate.exchange(config.getInfoUrl(), HttpMethod.GET, httpEntity, String.class);
    }

    private Map<String, String> extractUserInfo(ResponseEntity<String> responseEntity) {

        try {
            Map<String, String> userInfo = new HashMap<>();
            DocumentContext doc = JsonPath.parse(responseEntity.getBody());
            config.getFieldsToExtract().forEach((targetField, jsonPath) -> userInfo.put(targetField, doc.read(jsonPath)));
            return userInfo;
        } catch (Exception ex) {
            throw new AuthenticationException(INFO_EXTRACTION_ERROR);
        }
    }
}
