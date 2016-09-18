package com.b2s.sso.common.model;

import java.security.KeyStore;
import java.util.Map;

public interface CommonConfiguration {
    void reset();

    KeyStore getKeyStore();

    String getEntityID();

    void setEntityID(String value);

    void injectCredential(String certificate, String key);

    Map<String, String> getPrivateKeyPasswords();
}
