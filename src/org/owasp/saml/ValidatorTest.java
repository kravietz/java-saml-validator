package org.owasp.saml;

import static org.junit.Assert.*;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;

import org.junit.Test;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class ValidatorTest {

    @Test
    public void testValidateSAML1() throws SAXException, IOException, ParserConfigurationException, XPathExpressionException, KeyStoreException, NoSuchAlgorithmException, CertificateException, MarshalException, XMLSignatureException, InvalidKeySpecException {

        Validator val = new Validator("documents/signer1.der", "schemas/soap-envelope.xsd",
                // basic XPath syntax
                "/soape:Envelope/soape:Header/wsse:Security/ds:Signature",
                "/soape:Envelope/soape:Body");

        // soap-envelope.xsd does not specify Id field so XML signature validator will crash if this is not specified
        val.setIdAttribute("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Id");

        assertTrue(val.validate("documents/file0.xml"));

    }

    /*
    @Test

    public void testValidateSAML2() throws SAXException, IOException, ParserConfigurationException, XPathExpressionException, KeyStoreException, NoSuchAlgorithmException, CertificateException, MarshalException, XMLSignatureException, InvalidKeySpecException {

        Validator val = new Validator("documents/signer1.der", "schemas/soap-envelope.xsd",

                "/soape:Envelope/soape:Header/wsse:Security/ds:Signature",
                "/*[local-name()="Envelope" and namespace-uri()="http://schemas.xmlsoap.org/soap/envelope/"][1]/*[local-name()=\"Body\" and namespace-uri()=\"http://schemas.xmlsoap.org/soap/envelope/\"][1]");
                 /*[local-name()="Envelope" and namespace-uri()="http://schemas.xmlsoap.org/soap/envelope/"][1]/[local-name()="Body" and namespace-uri()="http://schemas.xmlsoap.org/soap/envelope/"][1]
        // soap-envelope.xsd does not specify Id field so XML signature validator will crash if this is not specified
        val.setIdAttribute("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Id");

        assertTrue(val.validate("documents/file0.xml"));

    }
    */

    /*
     * All "GG" tests are based on private documents that are not being published.
     */
    @Test
    public void testValidateGG1() throws SAXException, IOException, ParserConfigurationException, XPathExpressionException, KeyStoreException, NoSuchAlgorithmException, CertificateException, MarshalException, XMLSignatureException, InvalidKeySpecException {

        Validator val = new Validator("documents/gg.der", "schemas/WS-Trust.xsd",
                "/wst:RequestSecurityTokenResponse/:Signature",
                "/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken/saml:Assertion");

        // soap-envelope.xsd does not specify Id field so XML signature validator will crash if this is not specified
        val.setIdAttribute(null, "AssertionID");

        assertTrue(val.validate("documents/ggindividual.xml"));

    }

    @Test
    public void testValidateGG2() throws SAXException, IOException, ParserConfigurationException, XPathExpressionException, KeyStoreException, NoSuchAlgorithmException, CertificateException, MarshalException, XMLSignatureException, InvalidKeySpecException {

        Validator val = new Validator("documents/gg.der", "schemas/WS-Trust.xsd",
                "/wst:RequestSecurityTokenResponse/:Signature",
                "/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken/saml:Assertion");

        // soap-envelope.xsd does not specify Id field so XML signature validator will crash if this is not specified
        val.setIdAttribute(null, "AssertionID");

        assertTrue(val.validate("documents/ggagent.xml"));

    }

    @Test
    public void testValidateGG3() throws SAXException, IOException, ParserConfigurationException, XPathExpressionException, KeyStoreException, NoSuchAlgorithmException, CertificateException, MarshalException, XMLSignatureException, InvalidKeySpecException {

        Validator val = new Validator("documents/gg.der", "schemas/WS-Trust.xsd",
                "/wst:RequestSecurityTokenResponse/:Signature",
                "/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken/saml:Assertion");

        // soap-envelope.xsd does not specify Id field so XML signature validator will crash if this is not specified
        val.setIdAttribute(null, "AssertionID");

        assertTrue(val.validate("documents/ggorganisation.xml"));

    }

    @Test
    public void testValidateGG4() throws SAXException, IOException, ParserConfigurationException, XPathExpressionException, KeyStoreException, NoSuchAlgorithmException, CertificateException, MarshalException, XMLSignatureException, InvalidKeySpecException {

        Validator val = new Validator("documents/gg.der", "schemas/WS-Trust.xsd",
                "/wst:RequestSecurityTokenResponse/:Signature",
                "/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken/saml:Assertion");

        // soap-envelope.xsd does not specify Id field so XML signature validator will crash if this is not specified
        val.setIdAttribute(null, "AssertionID");

        assertFalse(val.validate("documents/gginvalid.xml"));

    }

    @Test
    public void testValidateGG5() throws SAXException, IOException, ParserConfigurationException, XPathExpressionException, KeyStoreException, NoSuchAlgorithmException, CertificateException, MarshalException, XMLSignatureException, InvalidKeySpecException {

        Validator val = new Validator("documents/gg.der", "schemas/WS-Trust.xsd",
                "/wst:RequestSecurityTokenResponse/:Signature",
                "/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken/saml:Assertion");

        // soap-envelope.xsd does not specify Id field so XML signature validator will crash if this is not specified
        val.setIdAttribute(null, "AssertionID");

        assertTrue(val.validate("documents/ggperformance.xml"));

    }

    @Test
    public void testValidateGG6() throws SAXException, IOException, ParserConfigurationException, XPathExpressionException, KeyStoreException, NoSuchAlgorithmException, CertificateException, MarshalException, XMLSignatureException, InvalidKeySpecException {

        Validator val = new Validator("documents/gg.der", "schemas/WS-Trust.xsd",
                "/wst:RequestSecurityTokenResponse/:Signature",
                "/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken/saml:Assertion");

        // soap-envelope.xsd does not specify Id field so XML signature validator will crash if this is not specified
        val.setIdAttribute(null, "AssertionID");

        assertTrue(val.validate("documents/ggperformance2.xml"));

    }



}
