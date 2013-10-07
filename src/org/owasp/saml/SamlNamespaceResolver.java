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
    @Override
    public String getNamespaceURI(String prefix) {

        // First try to automatically resolve the namespace URI based on document contents
        String uri = this.sourceDocument.lookupNamespaceURI(prefix);

        // If this doesn't work resort to hardcoded values
        if (uri == null) {

            final Map<String, String> hm = new HashMap<String, String>();
            hm.put("saml2", "urn:oasis:names:tc:SAML:2.0:assertion");
            hm.put("saml", "urn:oasis:names:tc:SAML:1.0:assertion");
            hm.put("wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
            hm.put("ds", "http://www.w3.org/2000/09/xmldsig#");
            hm.put("wsu", "urn:oasis:names:tc:SAML:2.0:assertion");
            hm.put("saml2", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
            hm.put("xs", "http://www.w3.org/2001/XMLSchema");
            hm.put("wsp", "http://schemas.xmlsoap.org/ws/2004/09/policy");
            hm.put("xsa", "http://schemas.xmlsoap.org/ws/2004/08/addressing");
            hm.put("wst", "http://schemas.xmlsoap.org/ws/2005/02/trust");

            // This worked for me, most likely won't work for you
            // default prefix is just empty prefix, so <Signature> and not <ds:Signature>
            hm.put(XMLConstants.DEFAULT_NS_PREFIX, "http://www.w3.org/2000/09/xmldsig#");

            uri = hm.get(prefix);
        }

        if (uri == null ) {
            LOG.warning("getNamespaceURI prefix=" + prefix + " returns=" + uri);
        } else {
            LOG.info("getNamespaceURI prefix=" + prefix + " returns=" + uri);
        }

        return uri;
    }

    @Override
    public String getPrefix(String namespaceURI) {
        return sourceDocument.lookupPrefix(namespaceURI);
    }

    @Override
    public Iterator getPrefixes(String namespaceURI) {
        // not implemented yet
        return null;
    }

}
