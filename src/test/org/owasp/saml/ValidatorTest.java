package test.org.owasp.saml; 

import org.junit.Test; 
import org.junit.Before; 
import org.junit.After;
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
* @since <pre>Oct 7, 2013</pre> 
* @version 1.0 
*/ 
public class ValidatorTest { 

@Before
public void before() throws Exception { 
} 

@After
public void after() throws Exception { 
} 

/** 
* 
* Method: getValidBody() 
* 
*/ 
@Test
public void testGetValidBody() throws Exception { 
//TODO: Test goes here... 
} 

/** 
* 
* Method: setIdAttribute(final String ns, final String attr) 
* 
*/ 
@Test
public void testSetIdAttribute() throws Exception { 
//TODO: Test goes here... 
} 

/** 
* 
* Method: validate(final String input) 
* 
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


/** 
* 
* Method: toFastXPath(String xpath, Document doc) 
* 
*/ 
@Test
public void testToFastXPath() throws Exception {
/* 
try { 
   Method method = Validator.getClass().getMethod("toFastXPath", String.class, Document.class); 
   method.setAccessible(true); 
   method.invoke(<Object>, <Parameters>); 
} catch(NoSuchMethodException e) { 
} catch(IllegalAccessException e) { 
} catch(InvocationTargetException e) { 
} 
*/ 
} 

} 
