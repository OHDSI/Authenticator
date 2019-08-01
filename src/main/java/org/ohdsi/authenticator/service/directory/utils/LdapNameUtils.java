package org.ohdsi.authenticator.service.directory.utils;

import org.springframework.ldap.InvalidNameException;
import org.springframework.ldap.support.LdapUtils;

public class LdapNameUtils {

    public static boolean isValidLdapName(String value) {
        try {
            LdapUtils.newLdapName(value);
            return true;
        } catch (InvalidNameException e) {
            return false;
        }
    }
}
