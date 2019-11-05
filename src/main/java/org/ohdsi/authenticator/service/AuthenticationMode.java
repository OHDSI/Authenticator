package org.ohdsi.authenticator.service;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum AuthenticationMode {
    STANDARD(Const.STANDARD),
    PROXY(Const.PROXY);

    private String value;

    //it is imposable to use enum in the annotation values, so this is workaround.
    public class Const {
        public static final String STANDARD = "STANDARD";
        public static final String PROXY = "PROXY";
    }

}
