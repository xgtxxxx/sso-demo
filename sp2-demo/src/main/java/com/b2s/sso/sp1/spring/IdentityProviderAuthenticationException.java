package com.b2s.sso.sp1.spring;

import org.springframework.security.core.AuthenticationException;

public class IdentityProviderAuthenticationException extends AuthenticationException {

    public IdentityProviderAuthenticationException(String msg, Object extraInformation) {
        super(msg, (Throwable) extraInformation);
    }


    public IdentityProviderAuthenticationException(String msg) {
        super(msg);
    }

}
