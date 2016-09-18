package com.b2s.sso.idp.spring.security;

import com.b2s.sso.common.model.AuthenticationMethod;
import com.b2s.sso.common.model.SimpleAuthentication;
import com.b2s.sso.common.model.IdpConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private IdpConfiguration idpConfiguration;
    
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final String name = authentication.getName();
        final String password = authentication.getCredentials().toString();

        if (idpConfiguration.getAuthentication() == AuthenticationMethod.Method.ALL) {
            final List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
            authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
            return new SimpleAuthentication(name, password, authorities);
        } else {
            final Collection<SimpleAuthentication> users = idpConfiguration.getUsers();
            for (final SimpleAuthentication user : users) {
                if (user.getPrincipal().equals(name) && user.getCredentials().equals(password)) {
                    return user;
                }
            }
            throw new AuthenticationException("Can not log in") {};
        }
    }

    public boolean supports(final Class method) {
        return method.equals(UsernamePasswordAuthenticationToken.class);
    }
}
