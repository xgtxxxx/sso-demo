package com.b2s.sso.common.saml;

import com.b2s.sso.common.model.CommonConfiguration;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.CredentialResolver;
import org.opensaml.xml.security.credential.KeyStoreCredentialResolver;


public class KeyStoreCredentialResolverDelegate implements CredentialResolver {

    private CommonConfiguration configuration;

    public Iterable<Credential> resolve(CriteriaSet criteriaSet) throws SecurityException {
        return getKeyStoreCredentialResolver().resolve(criteriaSet);
    }

    public Credential resolveSingle(CriteriaSet criteriaSet) throws SecurityException {
        return getKeyStoreCredentialResolver().resolveSingle(criteriaSet);
    }

    public KeyStoreCredentialResolver getKeyStoreCredentialResolver() {
        return new KeyStoreCredentialResolver(configuration.getKeyStore(), configuration.getPrivateKeyPasswords());
    }

    public void setConfiguration(final CommonConfiguration configuration) {
        this.configuration = configuration;
    }
}
