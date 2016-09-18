package com.b2s.sso.common.saml;

import org.opensaml.Configuration;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.security.SecurityPolicyException;
import org.opensaml.ws.security.SecurityPolicyRule;
import org.opensaml.xml.security.credential.CredentialResolver;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

public class SignatureSecurityPolicyRule implements InitializingBean, SecurityPolicyRule {

    private final static Logger log = LoggerFactory.getLogger(SignatureSecurityPolicyRule.class);

    private final CredentialResolver credentialResolver;
    private final SAMLSignatureProfileValidator samlSignatureProfileValidator;
    ExplicitKeySignatureTrustEngine trustEngine;

    public SignatureSecurityPolicyRule(CredentialResolver credentialResolver, SAMLSignatureProfileValidator samlSignatureProfileValidator) {
        super();
        this.credentialResolver = credentialResolver;
        this.samlSignatureProfileValidator = samlSignatureProfileValidator;
    }

    public void afterPropertiesSet() throws Exception {

        KeyInfoCredentialResolver keyInfoCredResolver =
                Configuration.getGlobalSecurityConfiguration().getDefaultKeyInfoCredentialResolver();

        trustEngine = new ExplicitKeySignatureTrustEngine(credentialResolver, keyInfoCredResolver);
    }

    public void evaluate(MessageContext messageContext) throws SecurityPolicyException {

        log.debug("evaluating signature of {}", messageContext);

        if (!(messageContext.getInboundMessage() instanceof SignableSAMLObject)) {
            throw new SecurityPolicyException("Inbound Message is not a SignableSAMLObject");
        }

        SignableSAMLObject samlMessage = (SignableSAMLObject) messageContext.getInboundMessage();

        checkSignatureProfile(samlMessage);
    }

    private void checkSignatureProfile(SignableSAMLObject samlMessage)
            throws SecurityPolicyException {
        try {
            final Signature signature = samlMessage.getSignature();
            if (signature != null) {
                samlSignatureProfileValidator.validate(signature);
            }
        } catch (ValidationException ve) {

            throw new SecurityPolicyException("Signature did not conform to SAML Signature profile", ve);
        }
    }
}
