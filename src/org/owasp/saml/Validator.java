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

    private String keyFile;
    private String schemaFile;
    private String signatureXPath;
    private String bodyXPath;

    /*
     * Validates digitally signed XML documents against a supplied XML schema
     * and public key certificate.
     *
     * @param keyFile certificate key file in DER forma (filename)
     * @param schemaFile schema file for the input document
     * @param signatureXPath XPath location of the Signature element in the validated document
     *                       Example: "/wst:RequestSecurityTokenResponse/:Signature"
     * @param bodyXPath  XPath location of the signed body element in the validated document
     *                  Example: "/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken/saml:Assertion"
     *
     */
    public Validator(final String keyFile, final String schemaFile,
                     final String signatureXPath, final String bodyXPath)  {
        this.keyFile = keyFile;
        this.schemaFile = schemaFile;
        this.signatureXPath = signatureXPath;
        this.bodyXPath = bodyXPath;
    }

    private Element validBody = null;
    private String idAttribute = null;
    private String idNamespace = null;

    /**
     * Returns XML structure that is likely to be authentic after
     * validate() call was successful.
     *
     * @return the assertion if validation was successful, null if not.
     */
    public Element getValidBody() {
        return this.validBody;
    }

    /*
     * Sets identifier attribute on XML node before validation is performed.
     * This is required on JDK 1.6.25+ and 1.7+ due to much stricter
     * reference checking compared with older versions. Typical error:
     *
     * javax.xml.crypto.dsig.XMLSignatureException:
     * javax.xml.crypto.URIReferenceException: com.sun.org.apache.xml.internal.security.utils.resolver.ResourceResolverException:
     * Cannot resolve element with ID
     *
     * @param ns namespace of the identifier attribute; null if the attribute uses no namespace
     * @param attr name of the identifier attribute (mandatory)
     *
     */
    public void setIdAttribute(final String ns, final String attr) {
        this.idNamespace = ns;
        this.idAttribute = attr;

    }

    /**
     * Perform schema and signature validation on supplied XML document.
     *
     * @param input the input document for validation
     * @return true if successful, false if not
     * @throws SAXException on XML parser errors
     * @throws IOException on file errors
     */
    public boolean validate(final String input)
            throws SAXException, IOException, // db.parse()
            ParserConfigurationException // factory.newDocumentBuilder()
            , XPathExpressionException // xpath.evaluate()
            , NoSuchAlgorithmException, CertificateException // ks.load()
            , MarshalException // unmarshal()
            , XMLSignatureException, InvalidKeySpecException {

        Element bodyElement;
        Element signatureElement;

        LOG.info("Validator starting...");
		
		/*
		 * Create base for XML document parser. Enable XML namespace processing, as SAML
		 * documents use namespaces. Enable XML validation, which is one of the safeguards against
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
    	 * All remaining schemas will be supplied through entity resolver (see below). The tricky
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

        final Map <String, Boolean> hm = new HashMap<>();
        // disable DTD to prevent override of ID elements
        hm.put("http://apache.org/xml/features/nonvalidating/load-dtd-grammar", false);
        // distable schemaLocation override and only rely on local EntityResolver
        hm.put("http://apache.org/xml/features/honour-all-schemaLocations", false);
        // validate schema
        hm.put("http://apache.org/xml/features/validation/schema", true);
        hm.put("http://apache.org/xml/features/validation/schema-full-checking", true);
        // additional features, not available in all parsers
        hm.put("http://apache.org/xml/features/validation/id-idref-checking", true);
        hm.put("http://apache.org/xml/features/validation/identity-constraint-checking", true);
        hm.put("http://apache.org/xml/features/standard-uri-conformant", true);
        hm.put("http://xml.org/sax/features/unicode-normalization-checking", true);

        for (Map.Entry<String, Boolean> entry : hm.entrySet()) {
            try {
                factory.setFeature(entry.getKey(), entry.getValue());
            } catch (Exception e) {
                LOG.warning("Unsupported XML parser feature " + entry.getKey());
            }
        }

    	/*
    	 * Create XML parser object from previously configured builder.
    	 */
        DocumentBuilder db = factory.newDocumentBuilder();
    	
    	/*
    	 * Assign a separate error handler to the XML parses. This wouldn't be really necessary
    	 * but it's Java requirement. If you use validation (and we do) you need to have an
    	 * error handler. Our error handler will just print what happened.  
    	 */
        db.setErrorHandler(new SamlErrorHandler());
        
         /*
          * Configure an entity resolver, function that will return appropriate schemas
          * to the parser on demand. This is needed for two reasons:
          * 1) parser would normally download them automatically, but it usually takes a lot of time and they are not cached;
          * 2) schemas that are referenced with non-URL addresses (not "http://") cannot be downloaded automatically
          */
        db.setEntityResolver(new SamlEntityResolver());
    	
    	 /* Finally load, parse and validate the XML document. Any XML structure manipulations should be
    	  * detected here and result in failed validation.
    	  */
        LOG.info("XML parsing and validation...");
        Document doc = db.parse(new FileInputStream(input));

        // Show the root element of the document and its namespace
        LOG.info("Input document root=" + doc.getFirstChild().getLocalName() + " namespace=" + doc.getFirstChild().getNamespaceURI());

        LOG.info("Xpath starting...");
		 /*
		  * Use XPath finder to extract Assertion and Signature elements. They will be
		  * necessary for further digital signature validation.
		  */
        XPath xpath = XPathFactory.newInstance().newXPath();

        xpath.setNamespaceContext(new SamlNamespaceResolver(doc));

        bodyXPath = toFastXPath(bodyXPath, doc);
        bodyElement = (Element) xpath.evaluate(bodyXPath, doc, XPathConstants.NODE);
        if(bodyElement == null) {
            LOG.severe("Body element not found in the document, exiting");
            return false;
        }
        LOG.info("body=" + bodyElement.getLocalName() );

        signatureXPath = toFastXPath(signatureXPath, doc);
        signatureElement = (Element) xpath.evaluate(signatureXPath, doc, XPathConstants.NODE);
        if(signatureElement == null) {
            LOG.severe("Signature element not found in the document, exiting");
            return false;
        }

        LOG.info("signature_element=" + signatureElement.getLocalName() );

        if(this.idAttribute != null) {
            if(idNamespace != null) {
                bodyElement.setIdAttributeNS(this.idNamespace, this.idAttribute, true);
            } else {
                bodyElement.setIdAttribute(this.idAttribute, true);
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
            LOG.warning("Signature failed core validation");
            boolean sv = signature.getSignatureValue().validate(valContext);
            LOG.info("signature validation status: " + sv);
            // check the validation status of each Reference
            Iterator i = signature.getSignedInfo().getReferences().iterator();
            for (int j=0; i.hasNext(); j++) {
                boolean refValid =
                        ((Reference) i.next()).validate(valContext);
                LOG.info("ref[" + j + "] validity status: " + refValid);
            }
        }

        return coreValidity;

    }

    /*
     * A very primitive conversion from standard XPath into hardened syntax. Only supports /a/b and /ns1:a/ns2:b syntax
     * (with any number of any levels). The input XPath expression must be absolute, i.e. it must start from /
     *
     * @param xpath Input XPath string
     * @param doc Validated document (for namespace resolution)
     *
     * Example:
     * Input: /soape:Envelope/soape:Body
     * Output: /*[local-name()="Envelope" and namespace-uri()="http://schemas.xmlsoap.org/soap/envelope/"][1]/*[local-name()="Body" and namespace-uri()="http://schemas.xmlsoap.org/soap/envelope/"][1]
     * Reference: http://www.nds.ruhr-uni-bochum.de/research/publications/xspres-closer/
     */
    private String toFastXPath(String xpath, Document doc) {
        String[] parts = xpath.split("/");
        SamlNamespaceResolver nsres = new SamlNamespaceResolver(doc);

        if(! xpath.startsWith("/")) {
            throw new IllegalArgumentException("XPath must be absoluve (start with /)")  ;
        }

        String output = "/*";

        for(String part : parts) {
            if (!output.endsWith("/*")) {
                output += "/*";
            }
             // we get ["soape:Envelope", ...]
            if(part.length() == 0)
                continue;

            String[] elemparts = part.split(":");
            // we get ["soape", "Envelope"]

            if (elemparts.length == 1) {
                // no namespace
                output += String.format("[local-name()=\"%s\"][1]", elemparts[0]);
            } else if (elemparts.length == 2) {
                // with namespace
                output += String.format("[local-name()=\"%s\" and namespace-uri()=\"%s\"][1]", elemparts[1], nsres.getNamespaceURI(elemparts[0]));
            }  else {
                throw new IllegalArgumentException("invalid XPath syntax: " + part);
            }
        }

        LOG.info("toFastXPath input= " + xpath + " output= " + output);
        return output;
    }

}
