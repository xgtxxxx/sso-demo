package com.b2s.sso.sp.spring;

import com.b2s.sso.common.saml.BindingAdapter;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.core.Response;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.xml.security.SecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Required;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SAMLResponseAuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {

    private final static Logger logger = LoggerFactory
            .getLogger(SAMLResponseAuthenticationProcessingFilter.class);

    private BindingAdapter bindingAdapter;

    @Required
    public void setBindingAdapter(BindingAdapter bindingAdapter) {
        this.bindingAdapter = bindingAdapter;
    }


    public SAMLResponseAuthenticationProcessingFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {

        logger.debug("Attempting authentication.");

        SAMLMessageContext messageContext = null;

        try {
            messageContext = bindingAdapter.extractSAMLMessageContext(request);
        } catch (MessageDecodingException me) {
            throw new ServiceProviderAuthenticationException("Could not decode SAML Response", me);
        } catch (SecurityException se) {
            throw new ServiceProviderAuthenticationException("Could not decode SAML Response", se);
        }

        logger.debug("Message received from issuer: " + messageContext.getInboundMessageIssuer());

        if (!(messageContext.getInboundSAMLMessage() instanceof Response)) {
            throw new ServiceProviderAuthenticationException("SAML Message was not a Response.");
        }

        String credentials = bindingAdapter.extractSAMLMessage(request);

        SAMLAuthenticationToken authRequest = new SAMLAuthenticationToken((Response) messageContext.getInboundSAMLMessage(), credentials, null);

        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
        logger.debug("authRequest.getDetails():" + authRequest.getDetails());
        RequestContextHolder.resetRequestAttributes();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        return this.getAuthenticationManager().authenticate(authRequest);
    }

}
