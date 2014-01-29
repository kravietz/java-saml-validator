/*
 * Copyright Pawel Krawczyk (c) 2014.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.owasp.saml;

import org.w3c.dom.Document;

import javax.xml.XMLConstants;
import javax.xml.namespace.NamespaceContext;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.logging.Logger;

class NamespaceResolver implements NamespaceContext {

    private final static Logger LOG = Logger.getLogger(NamespaceResolver.class.getName());

    private Document sourceDocument;

    /**
     * This constructor stores the source document to search the namespaces in
     * it.
     *
     * @param document
     *            source document
     */
    public NamespaceResolver(Document document) {
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

            final Map<String, String> hm = new HashMap<>();
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
            LOG.warning("null URI in getNamespaceURI prefix=" + prefix);
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
