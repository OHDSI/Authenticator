package org.ohdsi.authenticator.service;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AccessToken {

    private Type type;
    private String value;

    public enum Type {
        JWT, IAP
    }

    public static AccessToken jwt(String value) {
        return new AccessToken(Type.JWT, value);
    }

    public static AccessToken iap(String value) {
        return new AccessToken(Type.IAP, value);
    }

}
