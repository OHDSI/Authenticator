package org.ohdsi.authenticator.converter;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.apache.commons.lang3.StringUtils;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.ohdsi.authenticator.model.User;
import org.ohdsi.authenticator.service.authentication.config.AuthServiceConfig;
import org.ohdsi.authenticator.service.directory.ldap.UserMappingConfig;
import org.springframework.context.expression.MapAccessor;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.expression.spel.SpelMessage;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.util.CollectionUtils;


public class AttributesToUserConverter {

    public static final List<SpelMessage> FIELD_NOT_FOUND_MESSAGE_CODES = Arrays.asList(SpelMessage.PROPERTY_OR_FIELD_NOT_READABLE_ON_NULL, SpelMessage.PROPERTY_OR_FIELD_NOT_READABLE);
    private AuthServiceConfig config;

    public AttributesToUserConverter(AuthServiceConfig config) {

        this.config = config;
    }

    public User convert(Map<String, ? extends Object> attributesRawData) {

        return convert(null, attributesRawData);
    }

    public User convert(String username, Map<String, ? extends Object> attributesRawData) {

        SpringExpresionConverter expr = new SpringExpresionConverter(attributesRawData);

        UserMappingConfig fieldsToUser = config.getFieldsToExtract();

        if (fieldsToUser == null) {
            throw new AuthenticationException("There is no fieldsToExtract configuration property.");
        }

        return User.builder()
                .username(getUsername(expr, username, fieldsToUser))
                .email(expr.getStringValue(fieldsToUser.getEmail()))
                .firstName(expr.getStringValue(fieldsToUser.getFirstName()))
                .middleName(expr.getStringValue(fieldsToUser.getMiddleName()))
                .lastName(expr.getStringValue(fieldsToUser.getLastName()))
                .organization(expr.getStringValue(fieldsToUser.getOrganization()))
                .department(expr.getStringValue(fieldsToUser.getDepartment()))
                .affiliation(expr.getStringValue(fieldsToUser.getAffiliation()))
                .personalSummary(expr.getStringValue(fieldsToUser.getPersonalSummary()))
                .phone(expr.getStringValue(fieldsToUser.getPhone()))
                .mobile(expr.getStringValue(fieldsToUser.getPhone()))
                .address1(expr.getStringValue(fieldsToUser.getAddress1()))
                .city(expr.getStringValue(fieldsToUser.getCity()))
                .zipCode(expr.getStringValue(fieldsToUser.getZipCode()))
                .roles(getRoles(expr, fieldsToUser.getRoles(), fieldsToUser.getMemberOf()))
                .build();
    }

    private String getUsername(SpringExpresionConverter expr, String username, UserMappingConfig fieldToUser) {

        if (StringUtils.isNotEmpty(username)) {
            return username;
        }
        return expr.getStringValue(fieldToUser.getUsername());
    }

    private List<String> getRoles(SpringExpresionConverter expr, Map<String, String> roles, String expression) {

        if (StringUtils.isEmpty(expression) || CollectionUtils.isEmpty(roles)) {
            return Collections.emptyList();
        }

        List<?> rolesFromAttributes = expr.getValue(expression, List.class);
        if (CollectionUtils.isEmpty(rolesFromAttributes)) {
            return Collections.emptyList();
        }
        return roles.entrySet().stream()
                .filter(e -> rolesFromAttributes.contains(e.getValue()))
                .map(e -> e.getKey())
                .collect(Collectors.toList());
    }

    public static class SpringExpresionConverter {
        private ExpressionParser parser;
        private StandardEvaluationContext context;

        public SpringExpresionConverter(Map<String, ? extends Object> attributesRawData) {

            this.parser = new SpelExpressionParser();
            this.context = new StandardEvaluationContext(attributesRawData);
            this.context.addPropertyAccessor(new MapAccessor());
        }

        public String getStringValue(String expression) {

            return getValue(expression, String.class);
        }

        public <T> T getValue(String expression, Class<T> clazz) {

            try {
                return parser.parseExpression(expression).getValue(context, clazz);
            } catch (SpelEvaluationException ex) {
                if (FIELD_NOT_FOUND_MESSAGE_CODES.contains(ex.getMessageCode())) {
                    return null;
                }
                throw ex;
            }
        }
    }

}
