package org.ohdsi.authenticator.service;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.var;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.ohdsi.authenticator.model.AuthenticationRequest;
import org.ohdsi.authenticator.model.UserInfo;
import org.ohdsi.authenticator.security.JwtTokenProvider;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.ConfigurationPropertySource;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.stereotype.Service;
import org.springframework.util.ClassUtils;

import javax.annotation.PostConstruct;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.Map;

@Service
public class AuthenticationManager {

    private static final String METHODS_KEY = "authenticator.methods";
    private static final String BAD_CREDENTIALS_ERROR = "Bad credentials";
    private static final String METHOD_NOT_SUPPORTED_ERROR = "Method not supported";

    private ConfigurableEnvironment environment;
    private JwtTokenProvider jwtTokenProvider;
    private ObjectMapper objectMapper;

    private Map<String, AuthService> authServices = new HashMap<>();

    public AuthenticationManager(ConfigurableEnvironment environment, JwtTokenProvider jwtTokenProvider) {

        this.environment = environment;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @PostConstruct
    private void postConstruct() throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, IllegalAccessException, InstantiationException {

        initObjectMapper();
        initServices();
    }

    public UserInfo authenticate(String method, AuthenticationRequest request) {

        var authService = getForMethod(method);

        if (authService == null) {
            throw new AuthenticationException(METHOD_NOT_SUPPORTED_ERROR);
        }

        var authentication = authService.authenticate(request);

        if (!authentication.isAuthenticated()) {
            throw new AuthenticationException(BAD_CREDENTIALS_ERROR);
        }

        var userInfo = new UserInfo();
        userInfo.setUsername(authentication.getPrincipal().toString());
        userInfo.setAuthMethod(method);
        userInfo.setAdditionalInfo((Map) authentication.getDetails());
        userInfo.setToken(jwtTokenProvider.createToken(request.getUsername(), userInfo.getAdditionalInfo()));

        return userInfo;
    }

    private void initObjectMapper() {

        this.objectMapper = new ObjectMapper();
        this.objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        this.objectMapper.enable(DeserializationFeature.READ_ENUMS_USING_TO_STRING);
    }

    private void initServices() throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {

        Map<String, AuthMethodSettings> authMethodSettingsMap = loadAuthMethodsSettings();

        for (Map.Entry<String, AuthMethodSettings> entry : authMethodSettingsMap.entrySet()) {
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

    private Map<String, AuthMethodSettings> loadAuthMethodsSettings() {

        Iterable<ConfigurationPropertySource> sources = ConfigurationPropertySources.get(environment);
        var binder = new Binder(sources);
        Map<String, Map<String, String>> rawMethodsMap = binder.bind(METHODS_KEY, (Class<Map<String, Map<String, String>>>) (Class) Map.class).get();

        Map<String, AuthMethodSettings> configuration = new HashMap<>();
        rawMethodsMap.forEach((m, c) -> configuration.put(m, objectMapper.convertValue(c, AuthMethodSettings.class)));

        return configuration;
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
}
