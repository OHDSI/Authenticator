package org.ohdsi.authenticator.service.rest;

import lombok.Getter;
import lombok.Setter;
import org.ohdsi.authenticator.service.AuthServiceConfig;

import java.util.Map;

@Getter
@Setter
public class RestAuthServiceConfig extends AuthServiceConfig {

    private String url;
    private BodyFormat bodyFormat;
    private Map<String, String> params;
    private LoginSuccessCriteria loginSuccessCriteria;
    private TokenConfig token;
    private String infoUrl;

    public enum BodyFormat {
        JSON,
        FORMDATA;
    }

    @Getter
    @Setter
    public class TokenConfig {

        private HttpPart source;
        private String key;
        private String targetHeader;
        private String targetFormat;
    }

    public enum HttpPart {
        HEADERS,
        BODY;
    }
}
