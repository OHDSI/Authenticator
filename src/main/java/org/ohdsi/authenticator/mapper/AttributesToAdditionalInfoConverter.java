package org.ohdsi.authenticator.mapper;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.lang3.StringUtils;
import org.ohdsi.authenticator.service.authentication.config.AuthServiceConfig;
import org.springframework.context.expression.MapAccessor;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.expression.spel.SpelMessage;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

public class AttributesToAdditionalInfoConverter {

    public static final List<SpelMessage> FIEDL_NOT_FOUND_MESSAGE_CODES = Arrays.asList(SpelMessage.PROPERTY_OR_FIELD_NOT_READABLE_ON_NULL, SpelMessage.PROPERTY_OR_FIELD_NOT_READABLE);
    private ExpressionParser parser;
    private StandardEvaluationContext context;
    private AuthServiceConfig config;

    public AttributesToAdditionalInfoConverter(Map<String, String> rawData, AuthServiceConfig config) {

        this.config = config;
        parser = new SpelExpressionParser();
        context = new StandardEvaluationContext(rawData);
        context.addPropertyAccessor(new MapAccessor());
    }

    public Map<String, String> convert() {

        return convertAdditionalInfo(config.getFieldsToExtract());

    }

    private Map<String, String> convertAdditionalInfo(Map<String, String> fieldsToExtract) {

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
