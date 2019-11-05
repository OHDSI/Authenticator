package org.ohdsi.authenticator.service;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.PostConstruct;
import lombok.var;
import org.ohdsi.authenticator.config.AuthSchema;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.ohdsi.authenticator.model.AuthenticationToken;
import org.ohdsi.authenticator.model.UserInfo;
import org.pac4j.core.credentials.Credentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.ClassUtils;

public class AuthenticatorStandardMode implements Authenticator {
    protected static final Logger logger = LoggerFactory.getLogger(Authenticator.class.getName());
    public static final String METHOD_KEY = "method";
    private static final String BAD_CREDENTIALS_ERROR = "Bad credentials";
    private static final String METHOD_NOT_SUPPORTED_ERROR = "Method not supported";

    private AuthSchema authSchema;
    private TokenService tokenService;
    private TokenProvider tokenProvider;
    private ObjectMapper objectMapper;


    private Map<String, AuthService> authServices = new HashMap<>();

    public AuthenticatorStandardMode(AuthSchema authSchema,
                                     TokenService tokenService,
                                     TokenProvider tokenProvider) {

        this.authSchema = authSchema;
        this.tokenService = tokenService;
        this.tokenProvider = tokenProvider;
    }

    @PostConstruct
    private void postConstruct() throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, IllegalAccessException, InstantiationException {

        initObjectMapper();
        initServices();
    }

    @Override
    public UserInfo authenticate(String method, Credentials request) {
        AuthService authService = getForMethod(method);

        if (authService == null) {
            throw new AuthenticationException(METHOD_NOT_SUPPORTED_ERROR);
        }

        AuthenticationToken authentication = authService.authenticate(request);

        if (!authentication.isAuthenticated()) {
            throw new AuthenticationException(BAD_CREDENTIALS_ERROR);
        }

        return buildUserInfo(authentication, method);
    }

    @Override
    public String resolveUsername(String token) {
        return tokenService.resolveAdditionalInfo(token, Claims.SUBJECT, String.class);
    }

    @Override
    public UserInfo refreshToken(String token) {

        Claims claims = tokenProvider.validateTokenAndGetClaims(token);
        String usedMethod = claims.get(METHOD_KEY, String.class);
        AuthService authService = getForMethod(usedMethod);
        AuthenticationToken authentication = authService.refreshToken(claims);
        return buildUserInfo(authentication, usedMethod);
    }

    @Override
    public void invalidateToken(String token) {

        tokenProvider.invalidateToken(token);
    }

    private void initObjectMapper() {

        this.objectMapper = new ObjectMapper();
        this.objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    private void initServices() throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {

        for (Map.Entry<String, AuthMethodSettings> entry : authSchema.getMethods().entrySet()) {
            String method = entry.getKey();
            AuthMethodSettings authMethodSettings = entry.getValue();

            String authServiceClassName = authMethodSettings.getService();
            Class authServiceClass = ClassUtils.forName(authServiceClassName, this.getClass().getClassLoader());

            Class configClass = resolveRequiredConfigClass(authServiceClass);
            AuthServiceConfig config = resolveConfig(authMethodSettings.getConfig(), configClass);

            AuthService authService = constructAuthService(authServiceClass, config);
            authServices.put(method, authService);
        }
    }

    private Class<? extends AuthServiceConfig> resolveRequiredConfigClass(Class authServiceClass) {

        Constructor[] constructors = authServiceClass.getDeclaredConstructors();
        for (Constructor constructor : constructors) {
            Class[] params = constructor.getParameterTypes();
            if (params.length == 1 && AuthServiceConfig.class.isAssignableFrom(params[0])) {
                return params[0];
            }
        }

        throw new RuntimeException(String.format("%s doesn't have required constructor", authServiceClass.getCanonicalName()));
    }

    private <T> T resolveConfig(Map rawConfig, Class targetType) {

        return (T) objectMapper.convertValue(rawConfig, targetType);
    }

    private AuthService constructAuthService(Class authServiceClass, AuthServiceConfig config)
            throws NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {

        return (AuthService) authServiceClass.getDeclaredConstructor(config.getClass()).newInstance(config);
    }

    private AuthService getForMethod(String method) {

        return authServices.get(method);
    }

    private UserInfo buildUserInfo(AuthenticationToken authentication, String method) {

        String username = authentication.getPrincipal().toString();

        Map userAdditionalInfo = (Map) authentication.getDetails();
        userAdditionalInfo.put(METHOD_KEY, method);

        String token = tokenProvider.createToken(username, userAdditionalInfo, authentication.getExpirationDate());

        var userInfo = tokenService.resolveUser(token);
        userInfo.setAdditionalInfo(userAdditionalInfo);

        return userInfo;
    }
}
