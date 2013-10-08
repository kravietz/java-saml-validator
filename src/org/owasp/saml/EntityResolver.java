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

/**
 *
 */
package org.owasp.saml;

import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import java.io.FileInputStream;
import java.util.logging.Logger;

class EntityResolver implements org.xml.sax.EntityResolver {

    private final static Logger LOG = Logger.getLogger(EntityResolver.class.getName());

    @Override
    public InputSource resolveEntity (String publicId, String systemId) throws SAXException,  java.io.IOException
    {

        String file = null;

        if (systemId.endsWith("oasis-200401-wss-wssecurity-secext-1.0.xsd")) {
            file = "schemas/oasis-200401-wss-wssecurity-secext-1.0.xsd";
        } else if (systemId.endsWith("oasis-200401-wss-wssecurity-utility-1.0.xsd")) {
            file = "schemas/oasis-200401-wss-wssecurity-utility-1.0.xsd";
        } else if (systemId.endsWith("xml.xsd")) {
            file = "schemas/xml.xsd";
        } else if (systemId.endsWith("xmldsig-core-schema.xsd")) {
            file = "schemas/xmldsig-core-schema.xsd";
        } else if (systemId.endsWith("XMLSchema.dtd")) {
            file = "schemas/XMLSchema.dtd";
        } else if (systemId.endsWith("datatypes.dtd")) {
            file = "schemas/datatypes.dtd";
        } else if (systemId.endsWith("ws-policy.xsd")) {
            file = "schemas/ws-policy.xsd";
        } else if (systemId.equals("urn:oasis:names:tc:SAML:1.0:protocol")) {
            file = "schemas/saml-schema-protocol-1.1.xsd";
        } else if (systemId.equals("urn:oasis:names:tc:SAML:1.0:assertion")) {
            file = "schemas/saml-schema-assertion-1.0.xsd";
        } else if (systemId.endsWith("addressing/")) { // http://schemas.xmlsoap.org/ws/2004/08/addressing/
            file = "schemas/addressing.xsd";
        } else if (systemId.endsWith("oasis-200401-wss-wssecurity-secext-1.0.xsd")) {
            file = "schemas/oasis-200401-wss-wssecurity-secext-1.0.xsd";
        } else if (systemId.equals("urn:oasis:names:tc:SAML:2.0:assertion")) {
            file = "schemas/saml-schema-assertion-2.0.xsd";
        }

        LOG.info("resolveEntity query: systemId=" + systemId + " publicId=" + publicId + " returns \"" + file + "\"");

        return new InputSource(new FileInputStream(file));
    }
}