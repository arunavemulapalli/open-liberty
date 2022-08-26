/*******************************************************************************
 * Copyright (c) 2022 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.security.saml.sso20.token;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.core.Assertion;

import com.ibm.websphere.security.saml2.Saml20Token;
import com.ibm.ws.security.saml.error.SamlException;
import com.ibm.ws.security.saml.sso20.rs.ByteArrayDecoder;

import test.common.SharedOutputManager;

/**
 *
 */
public class Saml20TokenImplTest {
    
    static SharedOutputManager outputMgr = SharedOutputManager.getInstance();
    @Rule
    public TestRule managerRule = outputMgr;
    
    String samltokentext = "<saml2:Assertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_5a9aa7a5baba3e58916977ebb2345a1f\" IssueInstant=\"2022-08-25T22:33:30.320Z\" Version=\"2.0\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><saml2:Issuer xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">https://localhost:8960/idp/shibboleth</saml2:Issuer><saml2:Subject xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"><saml2:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:uid\" NameQualifier=\"https://localhost:8960/idp/shibboleth\" SPNameQualifier=\"https://localhost:8020/ibm/saml20/sp1\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">testuser</saml2:NameID><saml2:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml2:SubjectConfirmationData Address=\"127.0.0.1\" InResponseTo=\"_6KCNA7zJSPbN7RMnkLX231IilkCTCiAT\" NotOnOrAfter=\"2022-08-25T22:38:30.452Z\" Recipient=\"https://localhost:8020/ibm/saml20/sp1/acs\"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore=\"2022-08-25T22:33:30.320Z\" NotOnOrAfter=\"2022-08-25T22:38:30.320Z\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"><saml2:AudienceRestriction><saml2:Audience>https://localhost:8020/ibm/saml20/sp1</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant=\"2022-08-25T22:33:29.821Z\" SessionIndex=\"_d92695639bbe1513de38822c291b630b\" SessionNotOnOrAfter=\"2022-08-25T23:33:30.350Z\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"><saml2:SubjectLocality Address=\"127.0.0.1\"/><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement><saml2:AttributeStatement xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"><saml2:Attribute FriendlyName=\"WindowsDomainNameIdValue\" Name=\"WindowsDomainNameIdHack\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\"><saml2:AttributeValue>\"test_WindowsDomainNameIdValue\"</saml2:AttributeValue></saml2:Attribute><saml2:Attribute FriendlyName=\"uid\" Name=\"urn:oid:0.9.2342.19200300.100.1.1\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\"><saml2:AttributeValue>testuser</saml2:AttributeValue></saml2:Attribute><saml2:Attribute FriendlyName=\"EntityNameIdValue\" Name=\"EntityNameIdHack\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\"><saml2:AttributeValue>\"test_EntityNameIdValue\"</saml2:AttributeValue></saml2:Attribute><saml2:Attribute FriendlyName=\"persistentNameIdValue\" Name=\"persistentNameIdHack\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\"><saml2:AttributeValue>\"test_PersistentNameIdValue\"</saml2:AttributeValue></saml2:Attribute><saml2:Attribute FriendlyName=\"userUniqueIdentifier\" Name=\"userUniqueIdentifier\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\"><saml2:AttributeValue>test_userUniqueIdentifier</saml2:AttributeValue></saml2:Attribute><saml2:Attribute FriendlyName=\"userIdentifier\" Name=\"userIdentifier\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\"><saml2:AttributeValue>test_userIdentifier</saml2:AttributeValue></saml2:Attribute><saml2:Attribute FriendlyName=\"KerberosNameIdValue\" Name=\"KerberosNameIdHack\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\"><saml2:AttributeValue>\"test_KerberosNameIdValue\"</saml2:AttributeValue></saml2:Attribute><saml2:Attribute FriendlyName=\"group\" Name=\"groupHack\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\"><saml2:AttributeValue>testuser</saml2:AttributeValue></saml2:Attribute><saml2:Attribute FriendlyName=\"realmIdentifier\" Name=\"realmIdentifier\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\"><saml2:AttributeValue>test_realmIdentifier</saml2:AttributeValue></saml2:Attribute><saml2:Attribute FriendlyName=\"groupIdentifier\" Name=\"groupIdentifier\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\"><saml2:AttributeValue>test_groupIdentifier</saml2:AttributeValue></saml2:Attribute><saml2:Attribute FriendlyName=\"mail\" Name=\"urn:oid:0.9.2342.19200300.100.1.3\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\"><saml2:AttributeValue>testuser</saml2:AttributeValue></saml2:Attribute><saml2:Attribute FriendlyName=\"CustomizeNameIdValue\" Name=\"CustomizeNameIdHack\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\"><saml2:AttributeValue>\"test_CustomizeNameIdValue\"</saml2:AttributeValue></saml2:Attribute><saml2:Attribute FriendlyName=\"TransientNameIdValue\" Name=\"TransientNameIdHack\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\"><saml2:AttributeValue>\"test_TransientNameIdValue\"</saml2:AttributeValue></saml2:Attribute><saml2:Attribute FriendlyName=\"X509SubjectNameNameIdValue\" Name=\"X509SubjectNameNameIdHack\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\"><saml2:AttributeValue>\"test_X509SubjectNameNameIdValue\"</saml2:AttributeValue></saml2:Attribute><saml2:Attribute FriendlyName=\"email\" Name=\"urn:oid:0.9.2342.19200300.100.1.3\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\"><saml2:AttributeValue>testuser</saml2:AttributeValue></saml2:Attribute><saml2:Attribute FriendlyName=\"realmname\" Name=\"hackRealm\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\"><saml2:AttributeValue>CN=testuser,O=IBM,C=US</saml2:AttributeValue></saml2:Attribute><saml2:Attribute FriendlyName=\"EncryptedNameIdValue\" Name=\"EncryptedNameIdHack\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\"><saml2:AttributeValue xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xsd:string\">\"test_EncryptedNameIdValue\"</saml2:AttributeValue></saml2:Attribute></saml2:AttributeStatement></saml2:Assertion>";

    /**
     * @throws java.lang.Exception
     */
    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
    }

    /**
     * @throws java.lang.Exception
     */
    @AfterClass
    public static void tearDownAfterClass() throws Exception {
    }

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {
        outputMgr.trace("*=all");
    }

    /**
     * @throws java.lang.Exception
     */
    @After
    public void tearDown() throws Exception {
        outputMgr.trace("*=all=disabled");
    }

    /**
     * Test method for {@link com.ibm.ws.security.saml.sso20.token.Saml20TokenImpl#Saml20TokenImpl(org.opensaml.saml.saml2.core.Assertion)}.
     */
    @Test
    public void testSaml20TokenImplAssertion() {
        
        byte[] bytes = null;
        Saml20Token saml = null;
        String issuer = "https://localhost:8960/idp/shibboleth";
        try {
            bytes = samltokentext.getBytes("UTF-8");
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
            
            ByteArrayDecoder byteArrayDecoder = new ByteArrayDecoder();
            SAMLObject samlxmlobj = (SAMLObject) byteArrayDecoder.unmarshallMessage(byteArrayInputStream);
            if (samlxmlobj instanceof Assertion) {
                saml = new Saml20TokenImpl(((Assertion)samlxmlobj));
            }
        
            assertTrue("token is null", saml != null);
            assertEquals("expecting the issuer from the token to be = " + issuer + ", but it is different...", issuer, saml.getSAMLIssuerName());
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            fail("Unexpected exception was thrown: " + e);

        } catch (MessageDecodingException me) {
            me.printStackTrace();
            fail("Unexpected exception was thrown: " + me);

        } catch (SamlException se) {
            se.printStackTrace();
            fail("Unexpected exception was thrown: " + se);

        }
    }

}
