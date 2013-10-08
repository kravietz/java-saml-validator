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

package org.owasp.saml;

import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import java.util.logging.Logger;

public class ErrorHandler implements org.xml.sax.ErrorHandler {

    private final static Logger LOG = Logger.getLogger(ErrorHandler.class.getName());

    @Override
    public void warning(SAXParseException e) throws SAXException {
        LOG.warning("Warning " + e.getMessage());
        throw new SAXException("Parser warning " + e.getMessage());
    }

    @Override
    public void error(SAXParseException e) throws SAXException {
        LOG.warning("Error " + e.getMessage());
        throw new SAXException("Parser error " + e.getMessage());
    }

    @Override
    public void fatalError(SAXParseException e) throws SAXException {
        LOG.warning("Fatal " + e.getMessage());
        throw new SAXException("Parser fatal " + e.getMessage());
    }
}
