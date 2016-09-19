package com.b2s.sso.idp.model;

public interface IdpConfiguration extends com.b2s.sso.common.model.CommonConfiguration {
    java.util.Map<String, String> getAttributes();

    java.util.Collection<com.b2s.sso.common.model.SimpleAuthentication> getUsers();

    com.b2s.sso.common.model.AuthenticationMethod.Method getAuthentication();

    void setAuthentication(com.b2s.sso.common.model.AuthenticationMethod.Method method);
}
