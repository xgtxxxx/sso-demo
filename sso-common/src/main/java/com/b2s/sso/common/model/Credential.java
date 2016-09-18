package com.b2s.sso.common.model;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.io.Serializable;

@XmlRootElement
public class Credential implements Serializable {
    private static final long serialVersionUID = 1L;

    private String certificate;
    private String key;

    public String getCertificate() {
        return certificate;
    }

    @XmlElement
    public void setCertificate(final String certificate) {
        this.certificate = certificate;
    }

    public String getKey() {
        return key;
    }

    @XmlElement
    public void setKey(final String key) {
        this.key = key;
    }
}
