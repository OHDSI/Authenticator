package org.ohdsi.authenticator.service.rest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import lombok.var;
import net.minidev.json.JSONArray;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.ohdsi.authenticator.model.AuthenticationRequest;
import org.ohdsi.authenticator.model.AuthenticationToken;
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
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;

public class RestAuthService extends AuthService<RestAuthServiceConfig> {

    private static final String TOKEN_KEY = "token";

    public RestAuthService(RestAuthServiceConfig config) {

        super(config);
    }

    @Override
    public AuthenticationToken authenticate(AuthenticationRequest request) {

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
            String remoteToken = extractRemoteToken(responseEntity, config.getToken());

            var details = Stream.of(remoteToken)
                    .map(this::queryUserInfo)
                    .map(this::extractUserInfo)
                    .findFirst().orElseThrow(() -> new AuthenticationException(INFO_EXTRACTION_ERROR));
            details.put(TOKEN_KEY, remoteToken);

            authBuilder.setUserDetails(details);
            setExpirationDate(authBuilder, remoteToken);
        }

        return authBuilder.build();
    }

    @Override
    public AuthenticationToken refreshToken(Jws<Claims> claims) {

        if (Objects.nonNull(config.getRefresh())) {
            String remoteToken = claims.getBody().get(TOKEN_KEY).toString();
            AuthenticationBuilder authBuilder = new AuthenticationBuilder();

            RestTemplate restTemplate = new RestTemplate();
            MultiValueMap<String, String> headers = getHeadersWithToken(remoteToken);
            HttpEntity httpEntity = new HttpEntity(new HashMap<>(), headers);
            ResponseEntity<String> response = restTemplate.exchange(config.getRefresh().getUrl(), HttpMethod.POST, httpEntity, String.class);

            String newRemoteToken = extractRemoteToken(response, config.getRefresh());
            claims.getBody().put(TOKEN_KEY, newRemoteToken);

            setExpirationDate(authBuilder, newRemoteToken);

            return authBuilder
                    .setAuthenticated(true)
                    .setUsername(claims.getBody().getSubject())
                    .setUserDetails((Map) claims.getBody())
                    .build();
        } else {
            return super.refreshToken(claims);
        }
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

        String bodyPropCriteria = config.getLoginSuccessCriteria().getBodyProperty();
        if (Objects.nonNull(bodyPropCriteria)) {
            JSONArray res = JsonPath.parse(responseEntity.getBody()).read(bodyPropCriteria);
            success = success && res.size() > 0;
        }

        return success;
    }

    private String extractRemoteToken(ResponseEntity<String> responseEntity, TokenSource tokenSource) {

        String token = null;

        if (Objects.equals(tokenSource.getSource(), HttpPart.HEADERS)) {
            token = responseEntity.getHeaders().getFirst(tokenSource.getKey());
        } else if (Objects.equals(tokenSource.getSource(), HttpPart.BODY)) {
            token = JsonPath.parse(responseEntity.getBody()).read(tokenSource.getKey());
        }

        if (token == null) {
            throw new AuthenticationException(INFO_EXTRACTION_ERROR);
        }

        return token;
    }

    private MultiValueMap<String, String> getHeadersWithToken(String token) {

        return new LinkedMultiValueMap<String, String>() {{
            add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
            add(config.getToken().getTargetHeader(), String.format(config.getToken().getTargetFormat(), token));
        }};
    }

    private ResponseEntity<String> queryUserInfo(String token) {

        RestTemplate restTemplate = new RestTemplate();
        MultiValueMap<String, String> headers = getHeadersWithToken(token);
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

    private Date extractExpirationDate(String remoteToken) {

        try {
            Base64.Decoder decoder = Base64.getUrlDecoder();
            String[] parts = remoteToken.split("\\."); // Splitting header, payload and signature
            JsonNode payloadNode = new ObjectMapper().readTree(new String(decoder.decode(parts[1])));
            long exp = payloadNode.get("exp").asLong() * 1000;
            return new Date(exp);
        } catch (IOException e) {
            throw new AuthenticationException(INFO_EXTRACTION_ERROR);
        }
    }

    private void setExpirationDate(AuthenticationBuilder builder, String remoteToken) {

        if (config.getToken().isCopyExpirationDate()) {
            Date expirationDate = extractExpirationDate(remoteToken);
            builder.setExpirationDate(expirationDate);
        }
    }
}
