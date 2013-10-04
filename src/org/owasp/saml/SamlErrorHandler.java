package org.owasp.saml;

import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import java.util.logging.Logger;

public class SamlErrorHandler implements ErrorHandler {

    private final static Logger LOG = Logger.getLogger(SamlErrorHandler.class.getName());

    public void warning(SAXParseException e) throws SAXException {
        LOG.warning("Warning " + e.getMessage());
        throw new SAXException("Parser warning " + e.getMessage());
    }

    public void error(SAXParseException e) throws SAXException {
        LOG.warning("Error " + e.getMessage());
        throw new SAXException("Parser error " + e.getMessage());
    }

    public void fatalError(SAXParseException e) throws SAXException {
        LOG.warning("Fatal " + e.getMessage());
        throw new SAXException("Parser fatal " + e.getMessage());
    }
}
