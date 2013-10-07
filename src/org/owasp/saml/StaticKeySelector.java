package org.owasp.saml;

import javax.xml.crypto.*;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;
import java.util.logging.Logger;

/**
 * XML digital signature helper class to return just a single, configured X.509 public key certificate
 * for signature validation.
 */
public class StaticKeySelector extends KeySelector  {

    private final static Logger LOG = Logger.getLogger(StaticKeySelector.class.getName());

    private PublicKey pk;

    /**
     * Reads X.509 key in PEM format and stores it in the object. The key will be
     * then returned when select() method is called.
     *
     * @param filename PEM key filename
     * @throws FileNotFoundException the file not found exception
     */
    public StaticKeySelector(String filename) throws IOException, CertificateException {

        LOG.info("StaticKeySelector starting..." + filename);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate cert = cf.generateCertificate(new FileInputStream(filename));
        LOG.info("cert=" + cert);

        pk =  cert.getPublicKey();

        LOG.info("Loaded public key " + pk);

    }

    @Override
    public KeySelectorResult select(KeyInfo keyInfo,
                                    KeySelector.Purpose purpose, AlgorithmMethod method,
                                    XMLCryptoContext context) throws KeySelectorException {
        if (pk != null) {
            LOG.info("Returning key " + pk);
            return new SimpleKeySelectorResult();
        }   else {
            LOG.warning("Cannot find any public key");
            return null;
        }
    }

    private class SimpleKeySelectorResult implements KeySelectorResult {
        private Key key;

        /**
         * Instantiates a new Simple key selector result.
         */
        private SimpleKeySelectorResult() {
            key = pk;
        }

        @Override
        public Key getKey() {
            return pk;
        }
    }

}
