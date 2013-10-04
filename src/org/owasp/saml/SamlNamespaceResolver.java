package org.owasp.saml;

import org.w3c.dom.Document;

import javax.xml.XMLConstants;
import javax.xml.namespace.NamespaceContext;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.logging.Logger;

public class SamlNamespaceResolver implements NamespaceContext {

    private final static Logger LOG = Logger.getLogger(SamlNamespaceResolver.class.getName());

    private Document sourceDocument;

    /**
     * This constructor stores the source document to search the namespaces in
     * it.
     *
     * @param document
     *            source document
     */
    public SamlNamespaceResolver(Document document) {
        sourceDocument = document;
    }

    /**
     * The lookup for the namespace uris is delegated to the stored document.
     *
     * @param prefix
     *            to search for
     * @return uri
     */
    public String getNamespaceURI(String prefix) {

        String uri = null;
        final String SAML10 = "urn:oasis:names:tc:SAML:1.0:assertion";
        final String SAML20 = "urn:oasis:names:tc:SAML:2.0:assertion";
        final String WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
        final String DS = "http://www.w3.org/2000/09/xmldsig#";
        final String WSU = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

        uri =  sourceDocument.lookupNamespaceURI(prefix);

        if (uri == null) {

            final Map<String, String> hm = new HashMap<String, String>();
            hm.put("saml2", "urn:oasis:names:tc:SAML:2.0:assertion");
            hm.put("saml", "urn:oasis:names:tc:SAML:1.0:assertion");
            hm.put("wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
            hm.put("ds", "http://www.w3.org/2000/09/xmldsig#");
            hm.put(XMLConstants.DEFAULT_NS_PREFIX, "http://www.w3.org/2000/09/xmldsig#");
            hm.put("wsu", "urn:oasis:names:tc:SAML:2.0:assertion");
            hm.put("saml2", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
            hm.put("xs", "http://www.w3.org/2001/XMLSchema");
            hm.put("wsp", "http://schemas.xmlsoap.org/ws/2004/09/policy");
            hm.put("xsa", "http://schemas.xmlsoap.org/ws/2004/08/addressing");
            hm.put("wst", "http://schemas.xmlsoap.org/ws/2005/02/trust");

            uri = hm.get(prefix);
        }

        if (uri == null ) {
            LOG.warning("getNamespaceURI prefix=" + prefix + " returns=" + uri);
        } else {
            LOG.info("getNamespaceURI prefix=" + prefix + " returns=" + uri);
        }

        return uri;
    }

    public String getPrefix(String namespaceURI) {
        return sourceDocument.lookupPrefix(namespaceURI);
    }

    public Iterator getPrefixes(String namespaceURI) {
        // not implemented yet
        return null;
    }

}
