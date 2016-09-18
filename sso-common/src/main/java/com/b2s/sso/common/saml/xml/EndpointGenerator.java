package com.b2s.sso.common.saml.xml;

import org.apache.commons.lang.StringUtils;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.namespace.QName;

public class EndpointGenerator {

    private final static Logger logger = LoggerFactory.getLogger(EndpointGenerator.class);

    private XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

    public Endpoint generateEndpoint(QName service, String location, String responseLocation) {

        logger.debug("end point service: {}", service);
        logger.debug("end point location: {}", location);
        logger.debug("end point responseLocation: {}", responseLocation);

        SAMLObjectBuilder<Endpoint> endpointBuilder = (SAMLObjectBuilder<Endpoint>) builderFactory.getBuilder(service);
        Endpoint samlEndpoint = endpointBuilder.buildObject();

        samlEndpoint.setLocation(location);

        // this does not have to be set
        if (StringUtils.isNotEmpty(responseLocation))
            samlEndpoint.setResponseLocation(responseLocation);

        return samlEndpoint;
    }

}
