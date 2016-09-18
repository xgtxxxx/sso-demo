package com.b2s.sso.common.saml;

import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface BindingAdapter {

    public void sendSAMLMessage(SignableSAMLObject samlMessage, Endpoint endpoint, Credential signingCredential, HttpServletResponse response) throws MessageEncodingException;

    public SAMLMessageContext extractSAMLMessageContext(HttpServletRequest request) throws MessageDecodingException, SecurityException;

    public String extractSAMLMessage(HttpServletRequest request);

}
