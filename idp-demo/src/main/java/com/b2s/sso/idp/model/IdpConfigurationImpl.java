package com.b2s.sso.idp.model;

public class IdpConfigurationImpl extends com.b2s.sso.common.model.CommonConfigurationImpl implements IdpConfiguration {

    private final static org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(IdpConfigurationImpl.class);

    private java.util.Map<String, String> attributes = new java.util.TreeMap<String, String>();
    private java.util.Collection<com.b2s.sso.common.model.SimpleAuthentication> users = new java.util.ArrayList<com.b2s.sso.common.model.SimpleAuthentication>();
    private com.b2s.sso.common.model.AuthenticationMethod.Method authMethod;

    public IdpConfigurationImpl() {
        reset();
    }

    public void reset() {
        authMethod = com.b2s.sso.common.model.AuthenticationMethod.Method.USER;
        entityId = "http://mock-idp";
        attributes.clear();
        attributes.put("urn:mace:dir:attribute-def:uid", "john.doe");
        attributes.put("urn:mace:dir:attribute-def:cn", "John Doe");
        attributes.put("urn:mace:dir:attribute-def:givenName", "John");
        attributes.put("urn:mace:dir:attribute-def:sn", "Doe");
        attributes.put("urn:mace:dir:attribute-def:displayName", "John Doe");
        attributes.put("urn:mace:dir:attribute-def:mail", "j.doe@example.com");
        attributes.put("urn:mace:terena.org:attribute-def:schacHomeOrganization", "example.com");
        attributes.put("urn:mace:dir:attribute-def:eduPersonPrincipalName", "j.doe@example.com");
        attributes.put("urn:oid:1.3.6.1.4.1.1076.20.100.10.10.1", "guest");
        try {
            keyStore = java.security.KeyStore.getInstance("JKS");
            keyStore.load(null, keystorePassword.toCharArray());
            appendToKeyStore(keyStore, "http://mock-idp", "idp-crt.pem", "idp-key.pkcs8.der", keystorePassword.toCharArray());
            privateKeyPasswords.put("http://mock-idp", keystorePassword);
        } catch (Exception e) {
            LOGGER.error("Unable to create default keystore", e);
        }
        users.clear();
        java.util.List<org.springframework.security.core.GrantedAuthority> authorities = new java.util.ArrayList<org.springframework.security.core.GrantedAuthority>();
        authorities.add(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER"));
        authorities.add(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_ADMIN"));
        final com.b2s.sso.common.model.SimpleAuthentication admin = new com.b2s.sso.common.model.SimpleAuthentication("admin", "secret", authorities);
        users.add(admin);
        authorities = new java.util.ArrayList<org.springframework.security.core.GrantedAuthority>();
        authorities.add(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER"));
        final com.b2s.sso.common.model.SimpleAuthentication user= new com.b2s.sso.common.model.SimpleAuthentication("user", "secret", authorities);
        users.add(user);
    }

    public java.util.Map<String, String> getAttributes() {
        return attributes;
    }

    public java.util.Collection<com.b2s.sso.common.model.SimpleAuthentication> getUsers() {
        return users;
    }

    public com.b2s.sso.common.model.AuthenticationMethod.Method getAuthentication() {
        return authMethod;
    }

    public void setAuthentication(final com.b2s.sso.common.model.AuthenticationMethod.Method method) {
        this.authMethod = method;
    }

}
