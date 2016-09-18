package com.b2s.sso.common.model;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.io.Serializable;

@XmlRootElement
public class AuthenticationMethod implements Serializable {
    private static final long serialVersionUID = 1L;

    private String value;

    public String getValue() {
        return value;
    }

    @XmlElement
    public void setValue(final String value) {
        this.value = value;
    }

    public enum Method {
        USER, ALL
    }
}
