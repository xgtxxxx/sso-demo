package com.b2s.sso.idp.controllers;

import com.b2s.sso.common.model.SimpleAuthentication;
import com.b2s.sso.common.saml.BindingAdapter;
import com.b2s.sso.common.saml.xml.EndpointGenerator;
import com.b2s.sso.common.saml.xml.SAML2ValidatorSuite;
import com.b2s.sso.common.util.IDService;
import com.b2s.sso.common.util.TimeService;
import com.b2s.sso.idp.model.IdpConfiguration;
import com.b2s.sso.idp.saml.xml.AuthnResponseGenerator;
import com.b2s.sso.idp.spring.AuthnRequestInfo;
import org.apache.commons.lang.Validate;
import org.joda.time.DateTime;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.CredentialResolver;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Controller
public class SSOController {
    private static final Logger logger = LoggerFactory.getLogger(SSOController.class);

    @Autowired
    private BindingAdapter adapter;
    @Value("${AUTHN_RESPONDER_URI}")
    private String authnResponderURI;
    @Autowired
    private SAML2ValidatorSuite validatorSuite;
    @Autowired
    private TimeService timeService;
    @Autowired
    private IDService idService;
    @Value("${ASSERTION_VALIDITY_TIME_INS_SECONDS}")
    private int responseValidityTimeInSeconds;
    @Autowired
    private CredentialResolver credentialResolver;
    @Autowired
    private IdpConfiguration idpConfiguration;

    @RequestMapping("/login")
    public void login(final HttpServletRequest request, final HttpServletResponse response) throws ServletException, IOException {
        SAMLMessageContext messageContext = null;
        try {
            messageContext = adapter.extractSAMLMessageContext(request);
        } catch (final MessageDecodingException mde) {
            logger.error("Exception decoding SAML message", mde);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
        } catch (final SecurityException se) {
            logger.error("Exception decoding SAML message", se);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
        }
        final AuthnRequest authnRequest = (AuthnRequest) messageContext.getInboundSAMLMessage();
        try {
            validatorSuite.validate(authnRequest);
        } catch (final ValidationException ve) {
            logger.warn("AuthnRequest Message failed Validation", ve);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
        }
        final AuthnRequestInfo info = new AuthnRequestInfo(authnRequest.getAssertionConsumerServiceURL(), authnRequest.getID());
        logger.debug("AuthnRequest {} vefified.  Forwarding to SSOSuccessAuthnResponder", info);
        request.getSession().setAttribute(AuthnRequestInfo.class.getName(), info);
        logger.debug("forwarding to authnResponderURI: {}", authnResponderURI);
        request.getRequestDispatcher(authnResponderURI).forward(request, response);
    }

    @RequestMapping("/authnResponder")
    public void authnResponder(final HttpServletRequest request, final HttpServletResponse response) throws ServletException, IOException {
        final AuthnRequestInfo info = (AuthnRequestInfo) request.getSession().getAttribute(AuthnRequestInfo.class.getName());
        if (info == null) {
            logger.warn("Could not find AuthnRequest on the request.  Responding with SC_FORBIDDEN.");
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        logger.debug("AuthnRequestInfo: {}", info);
        final SimpleAuthentication authToken = (SimpleAuthentication) SecurityContextHolder.getContext().getAuthentication();
        final DateTime authnInstant = new DateTime(request.getSession().getCreationTime());

        final CriteriaSet criteriaSet = new CriteriaSet();
        criteriaSet.add(new EntityIDCriteria(idpConfiguration.getEntityID()));
        criteriaSet.add(new UsageCriteria(UsageType.SIGNING));
        Credential signingCredential = null;
        try {
            signingCredential = credentialResolver.resolveSingle(criteriaSet);
        } catch (org.opensaml.xml.security.SecurityException e) {
            logger.warn("Unable to resolve EntityID while signing", e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
        }
        Validate.notNull(signingCredential);

        final AuthnResponseGenerator authnResponseGenerator = new AuthnResponseGenerator(signingCredential, idpConfiguration.getEntityID(), timeService, idService, idpConfiguration);
        final EndpointGenerator endpointGenerator = new EndpointGenerator();

        final String remoteIP = request.getRemoteAddr();

        final Response authResponse = authnResponseGenerator.generateAuthnResponse(remoteIP, authToken, info.getAssertionConumerURL(), responseValidityTimeInSeconds, info.getAuthnRequestID(), authnInstant);
        final Endpoint endpoint = endpointGenerator.generateEndpoint(org.opensaml.saml2.metadata.AssertionConsumerService.DEFAULT_ELEMENT_NAME, info.getAssertionConumerURL(), null);

        request.getSession().removeAttribute(AuthnRequestInfo.class.getName());

        //we could use a different adapter to send the response based on request issuer...
        try {
            adapter.sendSAMLMessage(authResponse, endpoint, signingCredential, response);
        } catch (final MessageEncodingException mee) {
            logger.error("Exception encoding SAML message", mee);
            response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        }
    }
    @RequestMapping(value="/logout")
    public String logoutPage (final HttpServletRequest request, final HttpServletResponse response) {
        final Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null){
            new SecurityContextLogoutHandler().logout(request, response, auth);
        }
        return "redirect:/login";
    }
}
