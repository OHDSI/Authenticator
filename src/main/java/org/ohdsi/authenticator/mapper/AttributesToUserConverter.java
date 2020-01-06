package org.ohdsi.authenticator.mapper;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.apache.commons.lang3.StringUtils;
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

    public static final List<SpelMessage> FIEDL_NOT_FOUND_MESSAGE_CODES = Arrays.asList(SpelMessage.PROPERTY_OR_FIELD_NOT_READABLE_ON_NULL, SpelMessage.PROPERTY_OR_FIELD_NOT_READABLE);
    private ExpressionParser parser;
    private StandardEvaluationContext context;
    private AuthServiceConfig config;
    private String username;

    public AttributesToUserConverter(String username, Map<String, String> rawData, AuthServiceConfig config) {

        this.username = username;
        this.config = config;
        parser = new SpelExpressionParser();
        context = new StandardEvaluationContext(rawData);
        context.addPropertyAccessor(new MapAccessor());
    }

    public static AttributesToUserConverter of(String username, Map<String, String> rawData, AuthServiceConfig config) {

        return new AttributesToUserConverter(username, rawData, config);
    }

    public static AttributesToUserConverter of(Map<String, String> rawData, AuthServiceConfig config) {

        return new AttributesToUserConverter(null, rawData, config);
    }

    public User extractUserDetails() {

        UserMappingConfig fieldsToUser = config.getFieldsToUser();

        if (fieldsToUser == null) {
            return null;
        }

        return User.builder()
                .username(getUsername(username, fieldsToUser))
                .email(getValue(fieldsToUser.getEmail()))
                .firstname(getValue(fieldsToUser.getFirstName()))
                .middlename(getValue(fieldsToUser.getMiddleName()))
                .lastname(getValue(fieldsToUser.getLastName()))
                .organization(getValue(fieldsToUser.getOrganization()))
                .department(getValue(fieldsToUser.getDepartment()))
                .affiliation(getValue(fieldsToUser.getAffiliation()))
                .personalSummary(getValue(fieldsToUser.getPersonalSummary()))
                .phone(getValue(fieldsToUser.getPhone()))
                .mobile(getValue(fieldsToUser.getPhone()))
                .address1(getValue(fieldsToUser.getAddress1()))
                .city(getValue(fieldsToUser.getCity()))
                .zipCode(getValue(fieldsToUser.getZipCode()))
                .roles(getRoles(fieldsToUser.getRoles(), fieldsToUser.getMemberOf()))
                .build();
    }

    private String getUsername(String username, UserMappingConfig fieldToUser) {

        if (StringUtils.isNotEmpty(username)) {
            return username;
        }
        return getValue(fieldToUser.getUsername());
    }

    private List<String> getRoles(Map<String, String> roles, String expression) {

        if (StringUtils.isEmpty(expression) || CollectionUtils.isEmpty(roles)) {
            return Collections.emptyList();
        }

        List<?> rolesFromAttributes = parser.parseExpression(expression).getValue(context, List.class);
        if (CollectionUtils.isEmpty(rolesFromAttributes)) {
            return Collections.emptyList();
        }
        return roles.entrySet().stream()
                .filter(e -> rolesFromAttributes.contains(e.getValue()))
                .map(e -> e.getKey())
                .collect(Collectors.toList());
    }

    private String getValue(String expression) {

        try {
            return parser.parseExpression(expression).getValue(context, String.class);
        } catch (SpelEvaluationException ex) {
            if (FIEDL_NOT_FOUND_MESSAGE_CODES.contains(ex.getMessageCode())) {
                return null;
            }
            throw ex;
        }
    }

}
