package com.b2s.sso.idp.saml.xml;


import com.b2s.sso.common.model.AuthenticationMethod;
import com.b2s.sso.common.model.SimpleAuthentication;
import com.b2s.sso.common.saml.xml.IssuerGenerator;
import com.b2s.sso.common.util.IDService;
import com.b2s.sso.common.util.TimeService;
import com.b2s.sso.idp.model.IdpConfiguration;
import org.joda.time.DateTime;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;

import java.util.HashMap;
import java.util.Map;

public class AssertionGenerator {

    private final XMLObjectBuilderFactory builderFactory = org.opensaml.Configuration.getBuilderFactory();

    private final IssuerGenerator issuerGenerator;
    private final SubjectGenerator subjectGenerator;
    private final IDService idService;
    private final TimeService timeService;
    private final AuthnStatementGenerator authnStatementGenerator = new AuthnStatementGenerator();
    private final AttributeStatementGenerator attributeStatementGenerator = new AttributeStatementGenerator();
    private Credential signingCredential;
    private IdpConfiguration idpConfiguration;

    public AssertionGenerator(final Credential signingCredential, String issuingEntityName, TimeService timeService, IDService idService, IdpConfiguration idpConfiguration) {
        super();
        this.signingCredential = signingCredential;
        this.timeService = timeService;
        this.idService = idService;
        this.idpConfiguration = idpConfiguration;
        issuerGenerator = new IssuerGenerator(issuingEntityName);
        subjectGenerator = new SubjectGenerator(timeService);
    }

    public Assertion generateAssertion(String remoteIP, SimpleAuthentication authToken, String recepientAssertionConsumerURL, int validForInSeconds, String inResponseTo, DateTime authnInstant) {
        // org.apache.xml.security.utils.ElementProxy.setDefaultPrefix(namespaceURI, prefix).



        AssertionBuilder assertionBuilder = (AssertionBuilder) builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
        Assertion assertion = assertionBuilder.buildObject();

        Subject subject = subjectGenerator.generateSubject(recepientAssertionConsumerURL, validForInSeconds, authToken.getName(), inResponseTo, remoteIP);

        Issuer issuer = issuerGenerator.generateIssuer();

        AuthnStatement authnStatement = authnStatementGenerator.generateAuthnStatement(authnInstant);

        assertion.setIssuer(issuer);
        assertion.getAuthnStatements().add(authnStatement);
        assertion.setSubject(subject);

        // extends this
        // assertion.getAttributeStatements().add(attributeStatementGenerator.generateAttributeStatement(authToken.getAuthorities()));

        final Map<String,String> attributes = new HashMap<String, String>();
        attributes.putAll(idpConfiguration.getAttributes());

        if (idpConfiguration.getAuthentication() == AuthenticationMethod.Method.ALL) {
            attributes.put("urn:mace:dir:attribute-def:uid", authToken.getName());
        }

        assertion.getAttributeStatements().add(attributeStatementGenerator.generateAttributeStatement(attributes));

        assertion.setID(idService.generateID());
        assertion.setIssueInstant(timeService.getCurrentDateTime());

        signAssertion(assertion);

        return assertion;
    }

    private void signAssertion(final Assertion assertion) {

        Signature signature = (Signature) org.opensaml.Configuration.getBuilderFactory()
                .getBuilder(Signature.DEFAULT_ELEMENT_NAME)
                .buildObject(Signature.DEFAULT_ELEMENT_NAME);

        signature.setSigningCredential(signingCredential);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        assertion.setSignature(signature);

        try {
            org.opensaml.Configuration.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
        } catch (MarshallingException e) {
            e.printStackTrace();
        }
        try {
            Signer.signObject(signature);
        } catch (SignatureException e) {
            e.printStackTrace();
        }
    }


}
