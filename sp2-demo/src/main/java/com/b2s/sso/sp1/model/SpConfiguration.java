package com.b2s.sso.sp1.model;

import com.b2s.sso.common.model.CommonConfiguration;

public interface SpConfiguration extends CommonConfiguration {
    public void setSingleSignOnServiceURL(String singleSignOnServiceURL);
    public String getSingleSignOnServiceURL();
}
