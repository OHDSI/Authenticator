package org.ohdsi.authenticator.service;

import java.util.Map;

public abstract class AuthServiceConfig {

    private Map<String, String> fieldsToExtract;

    public Map<String, String> getFieldsToExtract() {

        return fieldsToExtract;
    }

    public void setFieldsToExtract(Map<String, String> fieldsToExtract) {

        this.fieldsToExtract = fieldsToExtract;
    }
}
