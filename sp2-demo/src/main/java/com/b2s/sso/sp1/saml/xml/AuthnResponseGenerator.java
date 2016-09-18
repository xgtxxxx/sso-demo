package com.b2s.sso.sp1.saml.xml;

import com.b2s.sso.common.model.SimpleAuthentication;
import com.b2s.sso.common.saml.xml.IssuerGenerator;
import com.b2s.sso.common.util.IDService;
import com.b2s.sso.common.util.TimeService;
import com.b2s.sso.common.model.IdpConfiguration;
import org.joda.time.DateTime;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.impl.ResponseBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.security.credential.Credential;
import org.springframework.security.core.AuthenticationException;

public class AuthnResponseGenerator {

    private final XMLObjectBuilderFactory builderFactory = org.opensaml.Configuration.getBuilderFactory();

    private final String issuingEntityName;

    private final IssuerGenerator issuerGenerator;
    private final AssertionGenerator assertionGenerator;
    private final IDService idService;
    private final TimeService timeService;

    StatusGenerator statusGenerator;

    public AuthnResponseGenerator(final Credential signingCredential, String issuingEntityName, TimeService timeService, IDService idService, IdpConfiguration idpConfiguration) {
        super();
        this.issuingEntityName = issuingEntityName;
        this.idService = idService;
        this.timeService = timeService;
        issuerGenerator = new IssuerGenerator(issuingEntityName);
        assertionGenerator = new AssertionGenerator(signingCredential, issuingEntityName, timeService, idService, idpConfiguration);
        statusGenerator = new StatusGenerator();
    }


    public Response generateAuthnResponse(String remoteIP, SimpleAuthentication authToken, String recepientAssertionConsumerURL, int validForInSeconds, String inResponseTo, DateTime authnInstant) {

        ResponseBuilder responseBuilder = (ResponseBuilder) builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME);
        Response authResponse = responseBuilder.buildObject();

        Issuer responseIssuer = issuerGenerator.generateIssuer();

        Assertion assertion = assertionGenerator.generateAssertion(remoteIP, authToken, recepientAssertionConsumerURL, validForInSeconds, inResponseTo, authnInstant);

        authResponse.setIssuer(responseIssuer);
        authResponse.setID(idService.generateID());
        authResponse.setIssueInstant(timeService.getCurrentDateTime());
        authResponse.setInResponseTo(inResponseTo);
        authResponse.getAssertions().add(assertion);
        authResponse.setDestination(recepientAssertionConsumerURL);
        authResponse.setStatus(statusGenerator.generateStatus(StatusCode.SUCCESS_URI));

        return authResponse;
    }

    public Response generateAuthnResponseFailure(String recepientAssertionConsumerURL, String inResponseTo, AuthenticationException ae) {

        ResponseBuilder responseBuilder = (ResponseBuilder) builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME);
        Response authResponse = responseBuilder.buildObject();

        Issuer responseIssuer = issuerGenerator.generateIssuer();

        authResponse.setIssuer(responseIssuer);
        authResponse.setID(idService.generateID());
        authResponse.setIssueInstant(timeService.getCurrentDateTime());
        authResponse.setInResponseTo(inResponseTo);
        authResponse.setDestination(recepientAssertionConsumerURL);
        authResponse.setStatus(statusGenerator.generateStatus(StatusCode.RESPONDER_URI, StatusCode.AUTHN_FAILED_URI, ae.getClass().getName()));

        return authResponse;

    }
}