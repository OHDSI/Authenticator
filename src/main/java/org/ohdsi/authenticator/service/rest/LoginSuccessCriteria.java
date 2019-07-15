package org.ohdsi.authenticator.service.rest;

import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;

import java.util.HashMap;
import java.util.Map;

@Getter
@Setter
public class LoginSuccessCriteria {

    private HttpStatus status;
    /**
     * key - Header name
     * value - Header value
     */
    private Map<String, String> header = new HashMap<>();
    /**
     * key - JsonPath of property
     * value - value of the property
     */
    private Map<String, String> bodyProperty = new HashMap<>();
}
