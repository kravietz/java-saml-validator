/*
 * Copyright Pawel Krawczyk (c) 2013.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package test.org.owasp.saml;

import org.junit.Test;
import org.owasp.saml.Validator;
import org.xml.sax.SAXException;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Validator Tester.
 *
 * @author Pawel Krawczyk
 * @version 1.0
 * @since <pre>Oct 7, 2013</pre>
 */
public class ValidatorTest {

    /**
     * Method: validate(final String input)
     */
    @Test
    public void success_on_normal_file() throws SAXException, IOException, ParserConfigurationException, XPathExpressionException, KeyStoreException, NoSuchAlgorithmException, CertificateException, MarshalException, XMLSignatureException, InvalidKeySpecException {

        Validator val = new Validator("documents/signer1.der", "schemas/soap-envelope.xsd",
                // basic XPath syntax
                "/soape:Envelope/soape:Header/wsse:Security/ds:Signature",
                "/soape:Envelope/soape:Body");

        // soap-envelope.xsd does not specify Id field so XML signature validator will crash if this is not specified
        val.setIdAttribute("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Id");

        assertTrue(val.validate("documents/file0.xml"));

    }

    @Test
    public void fail_on_changed_body() throws SAXException, IOException, ParserConfigurationException, XPathExpressionException, KeyStoreException, NoSuchAlgorithmException, CertificateException, MarshalException, XMLSignatureException, InvalidKeySpecException {

        Validator val = new Validator("documents/signer1.der", "schemas/soap-envelope.xsd",
                // basic XPath syntax
                "/soape:Envelope/soape:Header/wsse:Security/ds:Signature",
                "/soape:Envelope/soape:Body");

        // soap-envelope.xsd does not specify Id field so XML signature validator will crash if this is not specified
        val.setIdAttribute("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Id");

        // this file has date changed in soap:Assertion attribute
        assertFalse(val.validate("documents/file1.xml"));

    }

    @Test
    public void fail_on_wrong_key() throws SAXException, IOException, ParserConfigurationException, XPathExpressionException, KeyStoreException, NoSuchAlgorithmException, CertificateException, MarshalException, XMLSignatureException, InvalidKeySpecException {

        Validator val = new Validator("documents/signer2.der", "schemas/soap-envelope.xsd",
                // basic XPath syntax
                "/soape:Envelope/soape:Header/wsse:Security/ds:Signature",
                "/soape:Envelope/soape:Body");

        // soap-envelope.xsd does not specify Id field so XML signature validator will crash if this is not specified
        val.setIdAttribute("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Id");

        assertFalse(val.validate("documents/file0.xml"));

    }


}
