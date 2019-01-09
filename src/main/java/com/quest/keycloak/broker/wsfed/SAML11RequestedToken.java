/*
 * Copyright 2016 Analytical Graphics, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package com.quest.keycloak.broker.wsfed;

import com.quest.keycloak.protocol.wsfed.sig.SAML11Signature;
import org.jboss.logging.Logger;
import org.keycloak.dom.saml.v1.assertion.SAML11AssertionType;
import org.keycloak.dom.saml.v1.assertion.SAML11AttributeStatementType;
import org.keycloak.dom.saml.v1.assertion.SAML11AttributeType;
import org.keycloak.dom.saml.v1.assertion.SAML11AudienceRestrictionCondition;
import org.keycloak.dom.saml.v1.assertion.SAML11ConditionAbstractType;
import org.keycloak.dom.saml.v1.assertion.SAML11ConditionsType;
import org.keycloak.dom.saml.v1.assertion.SAML11StatementAbstractType;
import org.keycloak.dom.saml.v1.assertion.SAML11SubjectStatementType;
import org.keycloak.dom.saml.v1.assertion.SAML11SubjectType;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.DocumentUtil;
import org.keycloak.saml.processing.core.parsers.saml.SAMLParser;
import org.keycloak.saml.processing.core.saml.v2.util.AssertionUtil;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.ws.rs.core.Response;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.security.PublicKey;
import java.util.List;

/**
 * The purpose of this class is to handle a SAML 1.1 token sent back from an external IdP. It has methods both to verify
 * that the token is valid, and to extract the elements needed by keycloak from the token.
 *
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @author <a href="mailto:alistair.doswald@elca.ch">Alistair Doswald</a>
 * @version $Revision: 1 $
 * @date 10/4/2016
 */
public class SAML11RequestedToken implements RequestedToken {

    //    private NameIDType subjectNameID;
    protected static final Logger logger = Logger.getLogger(SAML2RequestedToken.class);
    private SAML11AssertionType samlAssertion;
    private String wsfedResponse;

    /**
     * Builds the SAMLAssertion from the passed token as the basis of the SAML11RequestedToken.
     * @param wsfedResponse The wsfedResponse, in String format
     * @param token An object containing the SAML 1.1 assertion
     * @throws IOException Thrown if there's a problem parsing the token
     * @throws ParsingException Thrown if there's a problem parsing the token
     */
    public SAML11RequestedToken(String wsfedResponse, Object token) throws IOException, ParsingException {
        this.wsfedResponse = wsfedResponse;
        this.samlAssertion = getAssertionType(token);
    }


    public static boolean isSignatureValid(Element assertionElement, PublicKey publicKey) {
        try {
            Document doc = DocumentUtil.createDocument();
            Node n = doc.importNode(assertionElement, true);
            doc.appendChild(n);

            return new SAML11Signature().validate(doc, publicKey);
        } catch (Exception e) {
            logger.error("Cannot validate signature of assertion", e);
        }
        return false;
    }

    @Override
    public Response validate(PublicKey key, WSFedIdentityProviderConfig config, EventBuilder event, KeycloakSession session) {
        try {
            //We have to use the wsfedResponse and pull the document from it. The reason is the WSTrustParser sometimes re-organizes some attributes within the RequestedSecurityToken which breaks validation.
            Document doc = createXmlDocument(wsfedResponse);
            if(!isSignatureValid(extractSamlDocument(doc).getDocumentElement(), key)) {
                event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
                event.error(Errors.INVALID_SIGNATURE);
                return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_FEDERATED_IDENTITY_ACTION);
            }

            XMLGregorianCalendar notBefore = samlAssertion.getConditions().getNotBefore();
            //Add in a tiny bit of slop for small clock differences
            notBefore.add(DatatypeFactory.newInstance().newDuration(false, 0, 0, 0, 0, 0, 10));

            if(AssertionUtil.hasExpired(samlAssertion)) {
                event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
                event.error(Errors.EXPIRED_CODE);
                return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_FEDERATED_IDENTITY_ACTION);
            }

            if(!isValidAudienceRestriction(URI.create(config.getWsFedRealm()))) {
                event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
                event.error(Errors.INVALID_SAML_RESPONSE);
                return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_FEDERATED_IDENTITY_ACTION);
            }

        } catch (Exception e) {
            logger.error("Unable to validate signature", e);
            event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
            event.error(Errors.INVALID_SAML_RESPONSE);
            return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_FEDERATED_IDENTITY_ACTION);
        }

        return null;
    }

    /**
     * Returns the first name of the user. Expects a "givenname" attribute from which to extract the information
     * @return The first name of the user attempting to log in
     */
    @Override
    public String getFirstName() {
        if (!samlAssertion.getStatements().isEmpty()) {
            for (SAML11StatementAbstractType st : samlAssertion.getStatements()) {
                if (st instanceof  SAML11AttributeStatementType) {
                    SAML11AttributeStatementType attributeStatement = (SAML11AttributeStatementType)st;
                    for (SAML11AttributeType attribute : attributeStatement.get()) {
                        if ("givenname".equals(attribute.getAttributeName())
                                || JBossSAMLURIConstants.CLAIMS_GIVEN_NAME.get().equalsIgnoreCase(attribute.getAttributeName())) {
                            if (!attribute.get().isEmpty()) {
                                return attribute.get().get(0).toString();
                            }
                        }
                    }
                }
            }
        }
        return null;
    }

    /**
     * Returns the last name of the user. Expects a "surname" attribute from which to extract the information
     * @return The last name of the user attempting to log in
     */
    @Override
    public String getLastName() {
        if (!samlAssertion.getStatements().isEmpty()) {
            for (SAML11StatementAbstractType st : samlAssertion.getStatements()) {
                if (st instanceof  SAML11AttributeStatementType) {
                    SAML11AttributeStatementType attributeStatement = (SAML11AttributeStatementType)st;
                    for (SAML11AttributeType attribute : attributeStatement.get()) {
                        if ("surname".equals(attribute.getAttributeName())
                                || JBossSAMLURIConstants.CLAIMS_SURNAME.get().equalsIgnoreCase(attribute.getAttributeName())) {
                            if (!attribute.get().isEmpty()) {
                                return attribute.get().get(0).toString();
                            }
                        }
                    }
                }
            }
        }
        return null;
    }

    /**
     * Returns the username of the user as defined in the external IdP. This is necessary for keycloak to register a new
     * user from an external IdP.
     * First attempts to get the "name" attribute, then attempts to get the subject nameId or "nameidentifier" attribute
     * @return The username of the user attempting to log in
     */
    @Override
    public String getUsername() {
        String nameAttribute = getNameAttribute();
        if (nameAttribute != null) {
            return nameAttribute;
        }
        return getSubjectOrNameIdentifier();
    }

    /**
     * Returns the ID of the user as defined in the external IdP. This is necessary for keycloak to register a new
     * user from an external IdP.
     * Attempts to get in order: the subject nameId, the "nameidentifier" attribute and the "name" attribute
     * @return The ID of the user attempting to log in
     */
    @Override
    public String getId() {
        String id = getSubjectOrNameIdentifier();
        if (id != null) {
            return id;
        }
        return getNameAttribute();
    }

    /**
     * @return the "name" attribute from the SAML assertion
     */
    private String getNameAttribute(){
        if (!samlAssertion.getStatements().isEmpty()) {
            for (SAML11StatementAbstractType st : samlAssertion.getStatements()) {
                if (st instanceof  SAML11AttributeStatementType) {
                    SAML11AttributeStatementType attributeStatement = (SAML11AttributeStatementType)st;
                    // The "name" claim is a username
                    for (SAML11AttributeType attribute : attributeStatement.get()) {
                        if ("name".equalsIgnoreCase(attribute.getAttributeName())
                                || JBossSAMLURIConstants.CLAIMS_NAME.get().equalsIgnoreCase(attribute.getAttributeName())) {
                            if (!attribute.get().isEmpty()) {
                                return attribute.get().get(0).toString();
                            }
                        }
                    }
                }
            }
        }
        return null;
    }

    /**
     * @return The subject nameId or nameIdentifier from the SAML assertion
     */
    private String getSubjectOrNameIdentifier(){
        if (!samlAssertion.getStatements().isEmpty()) {
            for (SAML11StatementAbstractType st : samlAssertion.getStatements()) {
                if (st instanceof SAML11SubjectStatementType) {
                    SAML11SubjectStatementType subjectStatement = (SAML11SubjectStatementType)st;
                    SAML11SubjectType subject = subjectStatement.getSubject();
                    //first attempts to get subject
                    if (subject != null && subject.getChoice() != null)  {
                        SAML11SubjectType.SAML11SubjectTypeChoice choice = subject.getChoice();
                        if (choice.getNameID() != null) {
                            String nameId = choice.getNameID().getValue();
                            if (nameId != null && nameId.length() > 0) {
                                return nameId;
                            }
                        }
                    }
                    // The "nameidentifier" is a unique user id.
                    if (subjectStatement instanceof SAML11AttributeStatementType) {
                        SAML11AttributeStatementType attributeStatement = (SAML11AttributeStatementType)subjectStatement;
                        for (SAML11AttributeType attribute : attributeStatement.get()) {
                            if ("nameidentifier".equalsIgnoreCase(attribute.getAttributeName())
                                    || JBossSAMLURIConstants.CLAIMS_NAME_IDENTIFIER.get().equalsIgnoreCase(attribute.getAttributeName())) {
                                if (!attribute.get().isEmpty()) {
                                    return attribute.get().get(0).toString();
                                }
                            }
                        }
                    }
                }
            }
        }
        return null;
    }

    /**
     * Returns the email of the user. Expects a "emailaddress" attribute from which to extract the information
     * @return The email of the user attempting to log in
     */
    @Override
    public String getEmail() {
        if (!samlAssertion.getStatements().isEmpty()) {
            for (SAML11StatementAbstractType st : samlAssertion.getStatements()) {
                if (st instanceof  SAML11AttributeStatementType) {
                    SAML11AttributeStatementType attributeStatement = (SAML11AttributeStatementType)st;
                    for (SAML11AttributeType attribute : attributeStatement.get()) {
                        if ("emailaddress".equalsIgnoreCase(attribute.getAttributeName())
                                || JBossSAMLURIConstants.CLAIMS_EMAIL_ADDRESS_2005.get().equals(attribute.getAttributeName())) {
                            if (!attribute.get().isEmpty()) {
                                return attribute.get().get(0).toString();
                            }
                        }
                    }
                }
            }
        }
        return null;
    }


    @Override
    public String getSessionIndex() {
        //TODO: getSessionIndex still needs to be implemented
        return null;
    }

    /**
     * @return the original assertion
     */
    @Override
    public Object getToken() { return samlAssertion; }

    public boolean isValidAudienceRestriction(URI...uris) {
        List<URI> audienceRestriction = getAudienceRestrictions();

        if(audienceRestriction == null) {
            return true;
        }

        for (URI uri : uris) {
            if (audienceRestriction.contains(uri)) {
                return true;
            }
        }

        return false;
    }

    public List<URI> getAudienceRestrictions() {
        SAML11ConditionsType conditions = samlAssertion.getConditions();
        for(SAML11ConditionAbstractType condition : conditions.get()) {
            if(condition instanceof SAML11AudienceRestrictionCondition) {
                return ((SAML11AudienceRestrictionCondition) condition).get();
            }
        }

        return null;
    }

    /**
     * Parses the input SAML token to return a SAML11Assertion
     * @param token The input SAML token
     * @return the SAML 1.1 Assertion returned by the external IdP
     * @throws IOException Thrown if there's a problem parsing the token
     * @throws ParsingException Thrown if there's a problem parsing the token
     */
    public SAML11AssertionType getAssertionType(Object token) throws IOException, ParsingException {
        SAML11AssertionType assertionType =  null;
        ByteArrayInputStream bis = null;
        try {
            String assertionXml = DocumentUtil.asString(((Element) token).getOwnerDocument());

            bis = new ByteArrayInputStream(assertionXml.getBytes());
            SAMLParser parser = SAMLParser.getInstance();
            Object assertion = parser.parse(bis);

            assertionType = (SAML11AssertionType) assertion;
            return assertionType;
        } finally {
            if (bis != null) {
                bis.close();
            }
        }
    }

    public SAML11AssertionType getAssertionType() {
        return samlAssertion;
    }
}
