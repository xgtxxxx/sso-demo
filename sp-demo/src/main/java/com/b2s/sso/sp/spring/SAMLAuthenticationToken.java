package com.b2s.sso.sp.spring;

import org.opensaml.saml2.core.Response;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class SAMLAuthenticationToken extends AbstractAuthenticationToken {

    private final Object principal;
    private final Object credentials;

    /**
     * This constructor can be safely used by any code that wishes to create a
     * <code>UsernamePasswordAuthenticationToken</code>, as the {@link
     * #isAuthenticated()} will return <code>false</code>.
     *
     * @param response
     * @param credentials
     */
    public SAMLAuthenticationToken(Response response, String credentials, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = response;
        this.credentials = credentials;
        setAuthenticated(false);

    }

    /**
     * This constructor should only be used by <code>AuthenticationManager</code> or <code>AuthenticationProvider</code>
     * implementations that are satisfied with producing a trusted (i.e. {@link #isAuthenticated()} = <code>true</code>)
     * authentication token.
     *
     * @param user
     * @param credentials
     * @param authorities
     */
    public SAMLAuthenticationToken(User user, String credentials, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = user;
        this.credentials = credentials;
        super.setAuthenticated(true); // must use super, as we override
    }

    public Object getCredentials() {
        return credentials;
    }

    public Object getPrincipal() {
        return principal;
    }

    /* taken from Spring Security's UsernamePasswordAuthenticationToken implementation
      * @see org.springframework.security.authentication.AbstractAuthenticationToken#setAuthenticated(boolean)
      */
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        if (isAuthenticated) {
            throw new IllegalArgumentException(
                    "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        }

        super.setAuthenticated(false);
    }
}
