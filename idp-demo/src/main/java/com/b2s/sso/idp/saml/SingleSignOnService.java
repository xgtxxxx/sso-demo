package com.b2s.sso.idp.saml;

import com.b2s.sso.common.saml.BindingAdapter;
import com.b2s.sso.common.saml.xml.SAML2ValidatorSuite;
import com.b2s.sso.idp.spring.AuthnRequestInfo;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.web.WebAttributes;
import org.springframework.web.HttpRequestHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SingleSignOnService implements HttpRequestHandler {


    private static final Logger logger = LoggerFactory
            .getLogger(SingleSignOnService.class);

    @Autowired
    private final BindingAdapter adapter;
    @Value("AUTHN_RESPONDER_URI")
    private final String authnResponderURI;
    @Autowired
    private final SAML2ValidatorSuite validatorSuite;


    public SingleSignOnService(BindingAdapter adapter,
                               String authnResponderURI, SAML2ValidatorSuite validatorSuite) {
        super();
        this.adapter = adapter;
        this.authnResponderURI = authnResponderURI;
        this.validatorSuite = validatorSuite;
    }


    public void handleRequest(HttpServletRequest request,
                              HttpServletResponse response) throws ServletException, IOException {
        SAMLMessageContext messageContext = null;
        try {
            messageContext = adapter.extractSAMLMessageContext(request);
        } catch (MessageDecodingException mde) {
            logger.error("Exception decoding SAML message", mde);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
        } catch (SecurityException se) {
            logger.error("Exception decoding SAML message", se);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
        }

        AuthnRequest authnRequest = (AuthnRequest) messageContext.getInboundSAMLMessage();

        try {
            validatorSuite.validate(authnRequest);
        } catch (ValidationException ve) {
            logger.warn("AuthnRequest Message failed Validation", ve);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
        }

        AuthnRequestInfo info = new AuthnRequestInfo(authnRequest.getAssertionConsumerServiceURL(), authnRequest.getID());

        logger.debug("AuthnRequest {} vefified.  Forwarding to SSOSuccessAuthnResponder", info);
        request.getSession().setAttribute(AuthnRequestInfo.class.getName(), info);

        logger.debug("request.getSession().getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION) is {}", request.getSession().getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION));

        logger.debug("forwarding to authnResponderURI: {}", authnResponderURI);

        request.getRequestDispatcher(authnResponderURI).forward(request, response);

    }
}
