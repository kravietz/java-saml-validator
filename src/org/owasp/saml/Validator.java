package org.owasp.saml;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.validation.Schema;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.logging.Logger;
import javax.xml.validation.SchemaFactory;

/**
 * The type Validator.
 */
public class Validator {

    private final static Logger LOG = Logger.getLogger(Validator.class.getName());

    /*
     * XPath location of the Signature element in the validated document
     * Example: "/wst:RequestSecurityTokenResponse/:Signature"
     */
//    public String signatureXPath = null;

    /*
     * XPath location of the Assertion element in the validated document
     * Example: "/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken/saml:Assertion"
     */
//    public String bodyXPath = null;

    private Element bodyElement = null;
    private Element signatureElement = null;
    private Element validBody = null;
    private String idAttribute = null;
    private String idNamespace = null;

    /**
     * Obtains validated assertion node.
     *
     * @return the assertion if validation was successful, null if not.
     */
    public Element getValidBody() {
        return validBody;
    }

    /*
     * These are required on JDK 1.6.25+ and 1.7+ due to much stricter
     * reference checking compared with older versions. Typical error:
     *
     * javax.xml.crypto.dsig.XMLSignatureException:
     * javax.xml.crypto.URIReferenceException: com.sun.org.apache.xml.internal.security.utils.resolver.ResourceResolverException:
     * Cannot resolve element with ID
     *
     */
    public void setIdAttribute(String ns, String attr) {
        idNamespace = ns;
        idAttribute = attr;

    }

    /**
     * Validate boolean.
     *
     * @param input the input
     * @return the boolean
     * @throws SAXException the sAX exception
     * @throws IOException the iO exception
     * @throws ParserConfigurationException the parser configuration exception
     * @throws XPathExpressionException the x path expression exception
     * @throws KeyStoreException the key store exception
     * @throws NoSuchAlgorithmException the no such algorithm exception
     * @throws CertificateException the certificate exception
     * @throws MarshalException the marshal exception
     * @throws XMLSignatureException the xML signature exception
     * @throws InvalidKeySpecException the invalid key spec exception
     */
    public boolean validate(InputStream input, String keyFile, String schemaFile, String signatureXPath, String bodyXPath)
            throws SAXException, IOException, // db.parse()
            ParserConfigurationException // factory.newDocumentBuilder()
            , XPathExpressionException // xpath.evaluate()
            , KeyStoreException // KeyStore.getInstance()
            , NoSuchAlgorithmException, CertificateException // ks.load()
            , MarshalException // unmarshal()
            , XMLSignatureException, InvalidKeySpecException {

        LOG.info("Validator starting...");
		
		/*
		 * Create base for XML document parser. Enable XML namespace processing, as SAML
		 * org.owasp.saml.documents use namespaces. Enable XML validation, which is one of the safeguards against
		 * wrapping attacks.
		 */
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setValidating(true);

    	/*
    	 * Tell the factory that W3C XML schema language will be used.
    	 */
        factory.setAttribute("http://java.sun.com/xml/jaxp/properties/schemaLanguage", XMLConstants.W3C_XML_SCHEMA_NS_URI);
    	
    	/*
    	 * Specify the *initial* schema. This should be schema for the root document even if
    	 * it uses a number of other schemas (through namespaces).
    	 *
    	 * We supply it as InputSource because if it's supplied as string, the parser will
    	 * download it automatically each time the validator is run. InputSource will point
    	 * to the same file, just downloaded and stored locally. Example on how to supply it:
    	 * 
    	 * All remaining org.owasp.saml.schemas will be supplied through entity resolver (see below). The tricky
    	 * part seems to be that if the initial schema is not supplied via schemaSource, the entity resolver
    	 * will not be ever called.
    	 */
        factory.setAttribute("http://java.sun.com/xml/jaxp/properties/schemaSource", new FileInputStream(schemaFile));

        /*
         * Process XML documents within resource limits to prevent DoS.
         *
         * Reference:
         * http://docs.oracle.com/javase/7/docs/api/javax/xml/XMLConstants.html#FEATURE_SECURE_PROCESSING
         */
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

        /*
         * Prevent automated downloads of external DTD and schemas and only use those
         * provided locally by EntityResolver.
         *
         * References:
         * http://docs.oracle.com/javase/7/docs/api/javax/xml/XMLConstants.html#ACCESS_EXTERNAL_DTD
         * http://docs.oracle.com/javase/7/docs/api/javax/xml/XMLConstants.html#ACCESS_EXTERNAL_SCHEMA
         */

        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "file,jar");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "file,jar");

        /*
         *  Try to enable stricter validator settings if the XML parser implementation supports them
         *  and disable automation that could potentially lead to attacks.
         *
         *  Reference:
         *  http://xerces.apache.org/xerces2-j/features.html
         */
        /*
        final Map <String, Boolean> hm = new HashMap<String, Boolean>();
        hm.put("http://apache.org/xml/features/validation/schema", true);
        hm.put("http://apache.org/xml/features/validation/schema-full-checking", true);
        hm.put("http://apache.org/xml/features/validation/id-idref-checking", true);
        hm.put("http://apache.org/xml/features/validation/identity-constraint-checking", true);
        hm.put("http://apache.org/xml/features/standard-uri-conformant", true);
        hm.put("http://xml.org/sax/features/unicode-normalization-checking", true);
        hm.put("http://apache.org/xml/features/honour-all-schemaLocations", false);

        Iterator<Map.Entry<String, Boolean>> entries = hm.entrySet().iterator();
        while (entries.hasNext()) {
            Map.Entry<String, Boolean> entry = entries.next();;
            try {
                factory.setFeature(entry.getKey(), entry.getValue());
            } catch (Exception e) {
                LOG.warning("Unsupported XML parser feature" + entry.getKey());
            }
        }
        */
    	/*
    	 * Create XML parser object from previously configured base.
    	 */
        DocumentBuilder db = factory.newDocumentBuilder();
    	
    	/*
    	 * Assign a separate error handler to the XML parses. This wouldn't be really necessary
    	 * but it's Java requiremen. If you use validation (and we do) you need to have an
    	 * error handler. Our error handler will just print what happened.  
    	 */
        SamlErrorHandler err = new SamlErrorHandler();
        db.setErrorHandler(err);
        
         /*
          * Configure an entity resolver, function that will return appropriate org.owasp.saml.schemas
          * to the parser on demand. This is needed for two reasons:
          * 1) parser would normally download them automatically, but it usually takes a lot of time and they are not cached;
          * 2) org.owasp.saml.schemas that are referenced with non-URL addresses (not "http://") cannot be downloaded automatically
          */
        SamlEntityResolver res = new SamlEntityResolver();
        db.setEntityResolver(res);
    	
    	 /* Finally load, parse and validate the XML document. Any XML structure manipulations should be
    	  * detected here and result in failed validation.
    	  */
        LOG.info("XML parsing and validation...");
        Document doc = db.parse(input);

        // Show the root element of the document and its namespace
        LOG.info("Input document root=" + doc.getFirstChild().getLocalName() + " namespace=" + doc.getFirstChild().getNamespaceURI());

        LOG.info("Xpath starting...");
		 /*
		  * Use XPath finder to extract Assertion and Signature elements. They will be
		  * necessary for further digital signature validation.
		  */
        XPath xpath = XPathFactory.newInstance().newXPath();

        xpath.setNamespaceContext(new SamlNamespaceResolver(doc));

        bodyElement = (Element) xpath.evaluate(bodyXPath, doc, XPathConstants.NODE);

        if(bodyElement == null) {
            LOG.severe("Assertion element not found in the document, exiting");
            return false;
        }
        LOG.info("assertion=" + bodyElement.getLocalName() );

        signatureElement = (Element) xpath.evaluate(signatureXPath, doc, XPathConstants.NODE);
        if(signatureElement == null) {
            LOG.severe("Signature element not found in the document, exiting");
            return false;
        }

        LOG.info("signature_element=" + signatureElement.getLocalName() );

        if(idAttribute != null) {
            if(idNamespace != null) {
                bodyElement.setIdAttributeNS(idNamespace, idAttribute, true);
            } else {
                LOG.info("setIdAttribute " + idAttribute);
                bodyElement.setIdAttribute(idAttribute, true);
            }
        }

        LOG.info("XML digital signature validation starting...");
        
        /*
         * Create signature validator object.
         */
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        
        /*
         * Create signature validation context referring to this particular signature element
         * and certificate validation method.
         */
        DOMValidateContext valContext = new DOMValidateContext(new StaticKeySelector(keyFile), signatureElement);

        LOG.info("valContext=" + valContext);

        XMLSignature signature = fac.unmarshalXMLSignature(valContext);
        LOG.info("signature=" + signature.getSignatureValue().getId());

        boolean coreValidity = signature.validate(valContext);
        LOG.info("validity=" + coreValidity);

        if(coreValidity) {
        	/*
             * Copy the validation assertion element for user retrieval.
             */
            validBody = bodyElement;
        } else {
            System.err.println("Signature failed core validation");
            boolean sv = signature.getSignatureValue().validate(valContext);
            System.out.println("signature validation status: " + sv);
            // check the validation status of each Reference
            Iterator i = signature.getSignedInfo().getReferences().iterator();
            for (int j=0; i.hasNext(); j++) {
                boolean refValid =
                        ((Reference) i.next()).validate(valContext);
                System.out.println("ref["+j+"] validity status: " + refValid);
            }
        }

        return coreValidity;

    }

}
