package com.b2s.sso.sp1.model;

import com.b2s.sso.common.model.CommonConfigurationImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyStore;

public class SpConfigurationImpl extends CommonConfigurationImpl implements SpConfiguration {

    private static final Logger log = LoggerFactory.getLogger(SpConfigurationImpl.class);
    private final String defaultIdpSSOServiceURL;

    private String idpSSOServiceURL;

    public SpConfigurationImpl(String defaultIdpSSOServiceURL) {
        this.defaultIdpSSOServiceURL = defaultIdpSSOServiceURL;
        reset();
    }

    public void reset() {
        entityId = "http://mock-sp";
        try {
            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null, keystorePassword.toCharArray());
            appendToKeyStore(keyStore, "http://mock-sp", "idp-crt.pem", "idp-key.pkcs8.der", keystorePassword.toCharArray());
            privateKeyPasswords.put("http://mock-sp", keystorePassword);
            idpSSOServiceURL = defaultIdpSSOServiceURL;
        } catch (Exception e) {
            log.error("Unable to create default keystore", e);
        }
    }

    public void setSingleSignOnServiceURL(String idpSSOServiceURL) {
        this.idpSSOServiceURL = idpSSOServiceURL;
    }

    public String getSingleSignOnServiceURL() {
        return idpSSOServiceURL;
    }
}
