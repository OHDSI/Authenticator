package org.ohdsi.authenticator.service.authentication.authenticator;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import javax.annotation.PostConstruct;
import org.ohdsi.authenticator.config.AuthSchema;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.ohdsi.authenticator.service.AuthMethodSettings;
import org.ohdsi.authenticator.service.AuthService;
import org.ohdsi.authenticator.service.authentication.config.AuthServiceConfig;
import org.ohdsi.authenticator.service.authentication.AuthServiceProvider;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;

public class AuthServiceProviderImpl implements AuthServiceProvider {

    private AuthSchema authSchema;
    private ObjectMapper objectMapper;

    private Map<String, AuthService> authServices = new HashMap<>();

    public AuthServiceProviderImpl(AuthSchema authSchema) {

        this.authSchema = authSchema;
    }

    @PostConstruct
    private void postConstruct()  {

        initObjectMapper();
        initServices();
    }

    @Override
    public Optional<AuthService> getByMethod(String method) {
        if (StringUtils.isEmpty(method)) {
            return Optional.empty();
        }

        return sanitizeAuthMethodName(method)
                .map(m -> authServices.get(m));

    }

    private void initServices(){

        try {
            for (Map.Entry<String, AuthMethodSettings> entry : authSchema.getMethods().entrySet()) {
                String method = entry.getKey();
                AuthMethodSettings authMethodSettings = entry.getValue();

                String authServiceClassName = authMethodSettings.getService();
                Class authServiceClass = ClassUtils.forName(authServiceClassName, this.getClass().getClassLoader());

                Class configClass = resolveRequiredConfigClass(authServiceClass);
                AuthServiceConfig config = resolveConfig(authMethodSettings.getConfig(), configClass);

                AuthService authService = constructAuthService(authServiceClass, config, method);
                sanitizeAuthMethodName(method)
                        .ifPresent(m -> authServices.put(m, authService));
            }
        } catch (Exception ex) {
            throw new AuthenticationException("Wrong configuration. Check 'authenticator.methonds' properties", ex);
        }
    }

    private void initObjectMapper() {

        this.objectMapper = new ObjectMapper();
        this.objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    private Class<? extends AuthServiceConfig> resolveRequiredConfigClass(Class authServiceClass) {

        Constructor[] constructors = authServiceClass.getDeclaredConstructors();
        for (Constructor constructor : constructors) {
            Class[] params = constructor.getParameterTypes();
            if (params.length == 2 && AuthServiceConfig.class.isAssignableFrom(params[0])) {
                return params[0];
            }
        }

        throw new RuntimeException(String.format("%s doesn't have required constructor", authServiceClass.getCanonicalName()));
    }

    private <T> T resolveConfig(Map rawConfig, Class targetType) {

        return (T) objectMapper.convertValue(rawConfig, targetType);
    }

    private AuthService constructAuthService(Class authServiceClass, AuthServiceConfig config, String method)
            throws NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {

        return (AuthService) authServiceClass
                .getDeclaredConstructor(config.getClass(), String.class)
                .newInstance(config, method);
    }


    private Optional<String> sanitizeAuthMethodName(String method) {

        if (StringUtils.isEmpty(method)) {
            return Optional.empty();
        }
        return Optional.of(method.toLowerCase().trim());
    }

}
