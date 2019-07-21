package org.ohdsi.authenticator.service.github;

import lombok.Getter;

public class RedirectRequiredException extends RuntimeException {

    @Getter
    private String redirectUrl;

    public RedirectRequiredException(String redirectUrl) {

        this.redirectUrl = redirectUrl;
    }
}
