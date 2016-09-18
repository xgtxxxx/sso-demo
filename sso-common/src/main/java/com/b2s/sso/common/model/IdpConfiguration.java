package com.b2s.sso.common.model;

import java.util.Collection;
import java.util.Map;

public interface IdpConfiguration extends CommonConfiguration {
    Map<String, String> getAttributes();

    Collection<SimpleAuthentication> getUsers();

    AuthenticationMethod.Method getAuthentication();

    void setAuthentication(AuthenticationMethod.Method method);
}
