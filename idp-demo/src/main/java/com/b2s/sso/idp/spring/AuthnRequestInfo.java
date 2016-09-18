package com.b2s.sso.idp.spring;

import org.apache.commons.lang.builder.ToStringBuilder;

import java.io.Serializable;

public class AuthnRequestInfo implements Serializable {

    private final String assertionConumerURL;
    private final String authnRequestID;

    public AuthnRequestInfo(String assertionConumerURL, String authnRequestID) {
        super();
        this.assertionConumerURL = assertionConumerURL;
        this.authnRequestID = authnRequestID;
    }

    public String getAssertionConumerURL() {
        return assertionConumerURL;
    }


    public String getAuthnRequestID() {
        return authnRequestID;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this).
                append("assertionConumerURL", assertionConumerURL).
                append("authnRequestID", authnRequestID).
                toString();


    }


}