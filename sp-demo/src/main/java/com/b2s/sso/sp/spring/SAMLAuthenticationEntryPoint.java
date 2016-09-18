package com.b2s.sso.sp.spring;

import com.b2s.sso.common.saml.AuthnRequestGenerator;
import com.b2s.sso.common.saml.BindingAdapter;
import com.b2s.sso.common.saml.xml.EndpointGenerator;
import com.b2s.sso.common.util.IDService;
import com.b2s.sso.common.util.TimeService;
import com.b2s.sso.sp.model.SpConfiguration;
import org.apache.commons.lang.Validate;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.CredentialResolver;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Required;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SAMLAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private static final Logger log = LoggerFactory.getLogger(SAMLAuthenticationEntryPoint.class);

    private final TimeService timeService;
    private final IDService idService;

    private String assertionConsumerServiceURL;
    private BindingAdapter bindingAdapter;
    private CredentialResolver credentialResolver;

    private SpConfiguration spConfiguration;

    public SAMLAuthenticationEntryPoint(TimeService timeService, IDService idService) {
        super();
        this.timeService = timeService;
        this.idService = idService;
    }

    @Required
    public void setAssertionConsumerServiceURL(String assertionConsumerServiceURL) {
        this.assertionConsumerServiceURL = assertionConsumerServiceURL;
    }

    @Required
    public void setBindingAdapter(BindingAdapter bindingAdapter) {
        this.bindingAdapter = bindingAdapter;
    }


    @Required
    public void setCredentialResolver(CredentialResolver credentialResolver) {
        this.credentialResolver = credentialResolver;
    }

    public void setConfiguration(final SpConfiguration spConfiguration) {
        this.spConfiguration = spConfiguration;
    }

    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {

        AuthnRequestGenerator authnRequestGenerator = new AuthnRequestGenerator(spConfiguration.getEntityID(), timeService, idService);
        EndpointGenerator endpointGenerator = new EndpointGenerator();

        final String singleSignOnServiceURL = spConfiguration.getSingleSignOnServiceURL();

        final String assertionConsumerUrl = assertionConsumerServiceURL;

        Endpoint endpoint = endpointGenerator.generateEndpoint(SingleSignOnService.DEFAULT_ELEMENT_NAME, singleSignOnServiceURL, assertionConsumerUrl);

        AuthnRequest authnReqeust = authnRequestGenerator.generateAuthnRequest(singleSignOnServiceURL, assertionConsumerUrl);

        log.debug("Sending authnRequest to {}", singleSignOnServiceURL);

        try {
            CriteriaSet criteriaSet = new CriteriaSet();
            criteriaSet.add(new EntityIDCriteria(spConfiguration.getEntityID()));
            criteriaSet.add(new UsageCriteria(UsageType.SIGNING));

            Credential signingCredential = credentialResolver.resolveSingle(criteriaSet);
            Validate.notNull(signingCredential);

            bindingAdapter.sendSAMLMessage(authnReqeust, endpoint, signingCredential, response);
        } catch (MessageEncodingException mee) {
            log.error("Could not send authnRequest to Identity Provider.", mee);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        } catch (org.opensaml.xml.security.SecurityException e) {
            log.error("Unable to retrieve signing credential", e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }
}
