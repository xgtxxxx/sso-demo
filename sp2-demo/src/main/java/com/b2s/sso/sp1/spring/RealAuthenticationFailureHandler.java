package com.b2s.sso.sp1.spring;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class RealAuthenticationFailureHandler implements
        AuthenticationFailureHandler {

    private final static Logger logger = LoggerFactory
            .getLogger(RealAuthenticationFailureHandler.class);

    private final RequestCache requestCache;


    public RealAuthenticationFailureHandler(RequestCache requestCache) {
        super();
        this.requestCache = requestCache;
    }

    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response, AuthenticationException authenticationException)
            throws IOException, ServletException {

        SavedRequest savedRequest = requestCache.getRequest(request, response);

        logger.debug("saved Request: {}", savedRequest);

        if (authenticationException instanceof IdentityProviderAuthenticationException && savedRequest != null) {

            logger.warn("Authn Failure reported by the IDP.", authenticationException);
            logger.debug("Retry original request of {}", savedRequest.getRedirectUrl());
            response.sendRedirect(savedRequest.getRedirectUrl());
        } else {
            logger.warn("Unrecoverable authn failure. Sending to Forbidden", authenticationException);
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
        }
    }
}
