java-saml-validator
===================

Reference SAML assertion digital signature validator for Java. This class can be used to validate SAML tokens
and other documents using XML Digital Signature. It attempts to perform as thorough validation
as possible to counter attacks such as XML signature wrapping. See article for theory:

* [Secure SAML validation to prevent XML signature wrapping attacks](http://ipsec.pl/node/1119)

Usage:

    Validator val = new Validator(x509_certificate, xsd_schema,
                    xpath_of_signature_element,
                    xpath_of_body_element);

    status = val.validate("documents/file0.xml");

Example from the test suite:

    Validator val = new Validator("documents/signer1.der", "schemas/soap-envelope.xsd",
                    // basic XPath syntax
                    "/soape:Envelope/soape:Header/wsse:Security/ds:Signature",
                    "/soape:Envelope/soape:Body");

    // soap-envelope.xsd does not specify Id field so XML signature validator will crash if this is not specified
    val.setIdAttribute("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Id");

    assertTrue(val.validate("documents/file0.xml"));

I would like to thank to Juraj Somorovsky for his numerous comments and suggestions. I would like to thank to Juraj Somorovsky for his numerous comments and suggestions. All possible mistakes and innacuracies are mine.
