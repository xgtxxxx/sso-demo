package com.b2s.sso.sp1.spring;

import com.b2s.sso.sp1.saml.AssertionConsumer;
import org.opensaml.saml2.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class SAMLResponseAuthenticationProvider implements AuthenticationProvider {

    private final static Logger logger = LoggerFactory
            .getLogger(SAMLResponseAuthenticationProvider.class);

    private final AssertionConsumer assertionConsumer;

    public SAMLResponseAuthenticationProvider(AssertionConsumer assertionConsumer) {
        super();
        this.assertionConsumer = assertionConsumer;
    }

    public Authentication authenticate(Authentication submitted)
            throws AuthenticationException {

        logger.debug("attempting to authenticate: {}", submitted);

        User user = assertionConsumer.consume((Response) submitted.getPrincipal());

        SAMLAuthenticationToken authenticated = new SAMLAuthenticationToken(user, (String) submitted.getCredentials(), user.getAuthorities());

        authenticated.setDetails(submitted.getDetails());

        logger.debug("Returning with authentication token of {}", authenticated);

        return authenticated;

    }

    public boolean supports(Class<? extends Object> authentication) {
        return (SAMLAuthenticationToken.class.isAssignableFrom(authentication));
    }

}
