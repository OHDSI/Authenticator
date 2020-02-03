package org.ohdsi.authenticator.service.rest.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;

@Getter
@Setter
public class LoginSuccessCriteria {

    private HttpStatus status;
    /**
     * JsonPath rule that should return JSONArray.size() > 0
     */
    private String bodyProperty;
}
