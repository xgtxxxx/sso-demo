package com.b2s.sso.sp1.spring;

import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;
import org.apache.commons.lang.builder.ToStringBuilder;
import org.joda.time.DateTime;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;
import java.security.Principal;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

public class User implements Principal, Serializable {

    private static final long serialVersionUID = -7932614405771273993L;
    private final String name;
    private final String authenticationResponseIssuingEntityName;
    private final String authenticationAssertionIssuingEntityName;
    private final String authenticationResponseID;
    private final String authenticationAssertionID;
    private final DateTime authenticationResponseIssueInstant;
    private final DateTime authenticationAssertionIssueInstant;
    private final DateTime authenticationIssueInstant;

    private final Set<GrantedAuthority> authorities;

    public User(String name, String authenticationResponseIssuingEntityName,
                String authenticationAssertionIssuingEntityName,
                String authenticationResponseID,
                String authenticationAssertionID,
                DateTime authenticationResponseIssueInstant,
                DateTime authenticationAssertionIssueInstant,
                DateTime authenticationIssueInstant,
                Collection<? extends GrantedAuthority> authorities) {
        super();
        this.name = name;
        this.authenticationResponseIssuingEntityName = authenticationResponseIssuingEntityName;
        this.authenticationAssertionIssuingEntityName = authenticationAssertionIssuingEntityName;
        this.authenticationResponseID = authenticationResponseID;
        this.authenticationAssertionID = authenticationAssertionID;
        this.authenticationResponseIssueInstant = authenticationResponseIssueInstant;
        this.authenticationAssertionIssueInstant = authenticationAssertionIssueInstant;
        this.authenticationIssueInstant = authenticationIssueInstant;
        this.authorities = Collections.unmodifiableSet(sortAuthorities(authorities));
    }

    public String getAuthenticationResponseIssuingEntityName() {
        return authenticationResponseIssuingEntityName;
    }

    public String getAuthenticationAssertionIssuingEntityName() {
        return authenticationAssertionIssuingEntityName;
    }

    public DateTime getAuthenticationResponseIssueInstant() {
        return authenticationResponseIssueInstant;
    }

    public DateTime getAuthenticationAssertionIssueInstant() {
        return authenticationAssertionIssueInstant;
    }

    public DateTime getAuthenticationIssueInstant() {
        return authenticationIssueInstant;
    }

    public String getAuthenticationResponseID() {
        return authenticationResponseID;
    }

    public String getAuthenticationAssertionID() {
        return authenticationAssertionID;
    }

    public Collection<GrantedAuthority> getAuthorities() {
        return authorities;
    }

    public String getName() {
        return name;
    }

    /**
     * Returns true if this object's name is equal to the name of the passed in arg.
     */
    @Override
    public boolean equals(Object obj) {

        if (obj == null) {
            return false;
        }
        if (obj == this) {
            return true;
        }

        if (obj.getClass() != getClass()) {
            return false;
        }
        User rhs = (User) obj;
        return new EqualsBuilder()
                .append(name, rhs.name)
                .isEquals();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(517, 43).
                append(name).toHashCode();

    }

    @Override
    public String toString() {

        return new ToStringBuilder(this).
                append("name", name).
                append("authenticationResponseIssuingEntityName", authenticationResponseIssuingEntityName).
                append("authenticationAssertionIssuingEntityName", authenticationAssertionIssuingEntityName).
                append("authenticationResponseID", authenticationResponseID).
                append("authenticationAssertionID", authenticationAssertionID).
                append("authenticationResponseIssueInstant", authenticationResponseIssueInstant).
                append("authenticationAssertionIssueInstant", authenticationAssertionIssueInstant).
                append("authenticationIssueInstant", authenticationIssueInstant).
                append("authorities", authorities).
                toString();
    }

    //Taken From Spring Security's User impl
    private static SortedSet<GrantedAuthority> sortAuthorities(Collection<? extends GrantedAuthority> authorities) {
        SortedSet<GrantedAuthority> sortedAuthorities =
                new TreeSet<GrantedAuthority>(new AuthorityComparator());

        for (GrantedAuthority grantedAuthority : authorities) {
            sortedAuthorities.add(grantedAuthority);
        }

        return sortedAuthorities;
    }

    //Taken From Spring Security's User impl
    private static class AuthorityComparator implements Comparator<GrantedAuthority>, Serializable {
        public int compare(GrantedAuthority g1, GrantedAuthority g2) {

            if (g2.getAuthority() == null) {
                return -1;
            }

            if (g1.getAuthority() == null) {
                return 1;
            }

            return g1.getAuthority().compareTo(g2.getAuthority());
        }
    }

}
