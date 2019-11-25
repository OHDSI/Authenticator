package org.ohdsi.authenticator.service.rest.config;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TokenConfig extends TokenSource {
    private String targetHeader;
    private String targetFormat;
    private boolean copyExpirationDate = false;
}
