/**
 *
 */
package org.owasp.saml;

import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import java.io.FileInputStream;
import java.util.logging.Logger;

public class SamlEntityResolver implements EntityResolver {

    private final static Logger LOG = Logger.getLogger(SamlEntityResolver.class.getName());

    public InputSource resolveEntity (String publicId, String systemId) throws SAXException,  java.io.IOException
    {

        InputSource src = null;
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
        } else if (systemId.endsWith("addressing/")) { // http://org.owasp.saml.schemas.xmlsoap.org/ws/2004/08/addressing/
            file = "schemas/addressing.xsd";
        } else if (systemId.endsWith("oasis-200401-wss-wssecurity-secext-1.0.xsd")) {
            file = "schemas/oasis-200401-wss-wssecurity-secext-1.0.xsd";
        } else if (systemId.equals("urn:oasis:names:tc:SAML:2.0:assertion")) {
            file = "schemas/saml-schema-assertion-2.0.xsd";
        }

        LOG.info("resolveEntity query: systemId=" + systemId + " publicId=" + publicId + " returns \"" + file + "\"");

        src = new InputSource(new FileInputStream(file));
        return src;
    }
}