package org.ohdsi.authenticator.mapper;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.apache.commons.lang3.StringUtils;
import org.ohdsi.authenticator.model.UserInfo;
import org.ohdsi.authenticator.service.authentication.config.AuthServiceConfig;
import org.ohdsi.authenticator.service.directory.ldap.UserMappingConfig;
import org.springframework.context.expression.MapAccessor;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.expression.spel.SpelMessage;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.util.CollectionUtils;

public class AttributesToUserInfoConverter {

    public static final List<SpelMessage> FIEDL_NOT_FOUND_MESSAGE_CODES = Arrays.asList(SpelMessage.PROPERTY_OR_FIELD_NOT_READABLE_ON_NULL, SpelMessage.PROPERTY_OR_FIELD_NOT_READABLE);
    private ExpressionParser parser;
    private StandardEvaluationContext context;
    private AuthServiceConfig config;
    private String username;

    public AttributesToUserInfoConverter(String username, Map<String, String> rawData, AuthServiceConfig config) {

        this.username = username;
        this.config = config;
        parser = new SpelExpressionParser();
        context = new StandardEvaluationContext(rawData);
        context.addPropertyAccessor(new MapAccessor());
    }

    public UserInfo extractUserDetails() {

        return UserInfo.builder()
                .user(mapUser(username, config.getFieldsToUser()))
                .additionalInfo(mapDetails(config.getFieldsToExtract()))
                .build();
    }

    private UserInfo.User mapUser(String username, UserMappingConfig fieldToUser) {

        if (fieldToUser == null) {
            return null;
        }

        return UserInfo.User.builder()
                .username(getUsername(username, fieldToUser))
                .email(getValue(fieldToUser.getEmail()))
                .firstname(getValue(fieldToUser.getFirstName()))
                .middlename(getValue(fieldToUser.getMiddleName()))
                .lastname(getValue(fieldToUser.getLastName()))
                .organization(getValue(fieldToUser.getOrganization()))
                .department(getValue(fieldToUser.getDepartment()))
                .affiliation(getValue(fieldToUser.getAffiliation()))
                .personalSummary(getValue(fieldToUser.getPersonalSummary()))
                .phone(getValue(fieldToUser.getPhone()))
                .mobile(getValue(fieldToUser.getPhone()))
                .address1(getValue(fieldToUser.getAddress1()))
                .city(getValue(fieldToUser.getCity()))
                .zipCode(getValue(fieldToUser.getZipCode()))
                .roles(getRoles(fieldToUser.getRoles(), fieldToUser.getMemberOf()))
                .build();
    }

    private String getUsername(String username, UserMappingConfig fieldToUser) {

        if (StringUtils.isNotEmpty(username)) {
            return username;
        }
        return getValue(fieldToUser.getUsername());
    }

    private Map<String, String> mapDetails(Map<String, String> fieldsToExtract) {

        if (fieldsToExtract == null) {
            return Collections.emptyMap();
        }

        Map<String, String> details = new HashMap<>();
        fieldsToExtract.forEach((key, expression) -> {
            String value = getValue(expression);
            if (StringUtils.isNotEmpty(value)) {
                details.put(key, value);
            }
        });
        return details;
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
