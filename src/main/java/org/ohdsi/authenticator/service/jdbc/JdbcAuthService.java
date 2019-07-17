package org.ohdsi.authenticator.service.jdbc;

import com.zaxxer.hikari.HikariDataSource;
import lombok.var;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.ohdsi.authenticator.model.AuthenticationRequest;
import org.ohdsi.authenticator.model.AuthenticationToken;
import org.ohdsi.authenticator.service.AuthService;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.ClassUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

public class JdbcAuthService extends AuthService<JdbcAuthServiceConfig> {

    private static final String USERNAME_PARAM = "username";
    private static final String PASSWORD_PARAM = "password";

    private HikariDataSource ds;
    private PasswordEncoder passwordEncoder;

    public JdbcAuthService(JdbcAuthServiceConfig config) throws IllegalAccessException, InstantiationException, ClassNotFoundException {

        super(config);
        initConnectionPool();
        this.passwordEncoder = getPasswordEncoder();
    }

    @Override
    public AuthenticationToken authenticate(AuthenticationRequest request) {

        var ps = new NamedParameterJdbcTemplate(ds);
        var params = buildQueryParams(request);
        var details = ps.queryForObject(config.getQuery(), params, this::mapUserInfo);
        var isAuthenticated = isSuccessfulLogin(request, details.remove(PASSWORD_PARAM));
        return new AuthenticationBuilder()
            .setAuthenticated(isAuthenticated)
            .setUsername(request.getUsername())
            .setUserDetails(details)
            .build();
    }

    private void initConnectionPool() {

        HikariDataSource ds = new HikariDataSource();
        ds.setJdbcUrl(config.getJdbcUrl());
        ds.setUsername(config.getUsername());
        ds.setPassword(config.getPassword());
        this.ds = ds;
    }

    private PasswordEncoder getPasswordEncoder() throws ClassNotFoundException, IllegalAccessException, InstantiationException {

        return (PasswordEncoder) ClassUtils.forName(config.getPasswordEncoder(), this.getClass().getClassLoader()).newInstance();
    }

    private MapSqlParameterSource buildQueryParams(AuthenticationRequest request) {

        var params = new MapSqlParameterSource();
        params.addValue(USERNAME_PARAM, request.getUsername());
        return params;
    }

    private Map<String, String> mapUserInfo(ResultSet rs, int rowNum) {

        try {
            Map<String, String> result = new HashMap<>();
            result.put(PASSWORD_PARAM, rs.getString(PASSWORD_PARAM));
            for (String targetField : config.getFieldsToExtract().keySet()) {
                result.put(targetField, rs.getString(config.getFieldsToExtract().get(targetField)));
            }
            return result;
        } catch (SQLException ex) {
            throw new AuthenticationException(INFO_EXTRACTION_ERROR);
        }
    }

    private boolean isSuccessfulLogin(AuthenticationRequest request, String actualPassword) {

        return passwordEncoder.matches(request.getPassword(), actualPassword);
    }
}
