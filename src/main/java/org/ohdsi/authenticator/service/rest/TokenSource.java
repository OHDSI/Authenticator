package org.ohdsi.authenticator.service.rest;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public abstract class TokenSource {

    private HttpPart source;
    private String key;
}
