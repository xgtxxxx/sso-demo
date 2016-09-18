package com.b2s.sso.sp1.saml.xml;

import com.b2s.sso.common.util.TimeService;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationDataBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;

public class SubjectGenerator {

    private final XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
    private final TimeService timeService;

    public SubjectGenerator(TimeService timeService) {
        super();
        this.timeService = timeService;
    }

    public Subject generateSubject(String recepientAssertionConsumerURL, int validForInSeconds, String subjectName, String inResponseTo, String clientAddress) {

        //Response/Assertion/Subject/NameID
        NameIDBuilder nameIDBuilder = (NameIDBuilder) builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
        NameID nameID = nameIDBuilder.buildObject();
        nameID.setValue(subjectName);
        nameID.setFormat(NameIDType.UNSPECIFIED);

        //Response/Assertion/Subject
        SubjectBuilder subjectBuilder = (SubjectBuilder) builderFactory.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
        Subject subject = subjectBuilder.buildObject();

        subject.setNameID(nameID);

        SubjectConfirmationBuilder subjectConfirmationBuilder = (SubjectConfirmationBuilder) builderFactory.getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
        SubjectConfirmation subjectConfirmation = subjectConfirmationBuilder.buildObject();
        subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);

        SubjectConfirmationDataBuilder subjectConfirmationDataBuilder = (SubjectConfirmationDataBuilder) builderFactory.getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
        SubjectConfirmationData subjectConfirmationData = subjectConfirmationDataBuilder.buildObject();

        subjectConfirmationData.setRecipient(recepientAssertionConsumerURL);
        subjectConfirmationData.setInResponseTo(inResponseTo);
        subjectConfirmationData.setNotOnOrAfter(timeService.getCurrentDateTime().plusSeconds(validForInSeconds));
        subjectConfirmationData.setAddress(clientAddress);

        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);

        subject.getSubjectConfirmations().add(subjectConfirmation);

        return subject;
    }


}
