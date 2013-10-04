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

        Validator val = new Validator();

        final String bodyXPath = "/soape:Envelope/soape:Body";
        final String signatureXPath = "/soape:Envelope/soape:Header/wsse:Security/ds:Signature";
        final String schemaFile = "schemas/soap-envelope.xsd";
        final String keyFile = "documents/signer1.der";

        FileInputStream input = new FileInputStream("documents/file0.xml");

        // soap-envelope.xsd does not specify Id field so XML signature validator will crash if this is not specified
        val.setIdAttribute("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Id");

        assertTrue(val.validate(input, keyFile, schemaFile, signatureXPath, bodyXPath));

    }

    @Test
    public void testValidateGG1() throws SAXException, IOException, ParserConfigurationException, XPathExpressionException, KeyStoreException, NoSuchAlgorithmException, CertificateException, MarshalException, XMLSignatureException, InvalidKeySpecException {

        Validator val = new Validator();

        final String bodyXPath = "/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken/saml:Assertion";
        final String signatureXPath = "/wst:RequestSecurityTokenResponse/:Signature";
        final String schemaFile = "schemas/WS-Trust.xsd";
        final String keyFile = "documents/gg.der";

        FileInputStream input = new FileInputStream("documents/ggindividual.xml");

        // soap-envelope.xsd does not specify Id field so XML signature validator will crash if this is not specified
        val.setIdAttribute(null, "AssertionID");

        assertTrue(val.validate(input, keyFile, schemaFile, signatureXPath, bodyXPath));

    }

    @Test
    public void testValidateGG2() throws SAXException, IOException, ParserConfigurationException, XPathExpressionException, KeyStoreException, NoSuchAlgorithmException, CertificateException, MarshalException, XMLSignatureException, InvalidKeySpecException {

        Validator val = new Validator();

        final String bodyXPath = "/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken/saml:Assertion";
        final String signatureXPath = "/wst:RequestSecurityTokenResponse/:Signature";
        final String schemaFile = "schemas/WS-Trust.xsd";
        final String keyFile = "documents/gg.der";

        FileInputStream input = new FileInputStream("documents/ggagent.xml");

        // soap-envelope.xsd does not specify Id field so XML signature validator will crash if this is not specified
        val.setIdAttribute(null, "AssertionID");

        assertTrue(val.validate(input, keyFile, schemaFile, signatureXPath, bodyXPath));

    }

    @Test
    public void testValidateGG3() throws SAXException, IOException, ParserConfigurationException, XPathExpressionException, KeyStoreException, NoSuchAlgorithmException, CertificateException, MarshalException, XMLSignatureException, InvalidKeySpecException {

        Validator val = new Validator();

        final String bodyXPath = "/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken/saml:Assertion";
        final String signatureXPath = "/wst:RequestSecurityTokenResponse/:Signature";
        final String schemaFile = "schemas/WS-Trust.xsd";
        final String keyFile = "documents/gg.der";

        FileInputStream input = new FileInputStream("documents/ggorganisation.xml");

        // soap-envelope.xsd does not specify Id field so XML signature validator will crash if this is not specified
        val.setIdAttribute(null, "AssertionID");

        assertTrue(val.validate(input, keyFile, schemaFile, signatureXPath, bodyXPath));

    }

    @Test
    public void testValidateGG4() throws SAXException, IOException, ParserConfigurationException, XPathExpressionException, KeyStoreException, NoSuchAlgorithmException, CertificateException, MarshalException, XMLSignatureException, InvalidKeySpecException {

        Validator val = new Validator();

        final String bodyXPath = "/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken/saml:Assertion";
        final String signatureXPath = "/wst:RequestSecurityTokenResponse/:Signature";
        final String schemaFile = "schemas/WS-Trust.xsd";
        final String keyFile = "documents/gg.der";

        FileInputStream input = new FileInputStream("documents/gginvalid.xml");

        // soap-envelope.xsd does not specify Id field so XML signature validator will crash if this is not specified
        val.setIdAttribute(null, "AssertionID");

        assertFalse(val.validate(input, keyFile, schemaFile, signatureXPath, bodyXPath));

    }

    @Test
    public void testValidateGG5() throws SAXException, IOException, ParserConfigurationException, XPathExpressionException, KeyStoreException, NoSuchAlgorithmException, CertificateException, MarshalException, XMLSignatureException, InvalidKeySpecException {

        Validator val = new Validator();

        final String bodyXPath = "/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken/saml:Assertion";
        final String signatureXPath = "/wst:RequestSecurityTokenResponse/:Signature";
        final String schemaFile = "schemas/WS-Trust.xsd";
        final String keyFile = "documents/gg.der";

        FileInputStream input = new FileInputStream("documents/ggperformance.xml");

        // soap-envelope.xsd does not specify Id field so XML signature validator will crash if this is not specified
        val.setIdAttribute(null, "AssertionID");

        assertTrue(val.validate(input, keyFile, schemaFile, signatureXPath, bodyXPath));

    }

    @Test
    public void testValidateGG6() throws SAXException, IOException, ParserConfigurationException, XPathExpressionException, KeyStoreException, NoSuchAlgorithmException, CertificateException, MarshalException, XMLSignatureException, InvalidKeySpecException {

        Validator val = new Validator();

        final String bodyXPath = "/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken/saml:Assertion";
        final String signatureXPath = "/wst:RequestSecurityTokenResponse/:Signature";
        final String schemaFile = "schemas/WS-Trust.xsd";
        final String keyFile = "documents/gg.der";

        FileInputStream input = new FileInputStream("documents/ggperformance2.xml");

        // soap-envelope.xsd does not specify Id field so XML signature validator will crash if this is not specified
        val.setIdAttribute(null, "AssertionID");

        assertTrue(val.validate(input, keyFile, schemaFile, signatureXPath, bodyXPath));

    }



}
