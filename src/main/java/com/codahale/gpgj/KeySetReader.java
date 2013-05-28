package com.codahale.gpgj;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * A reader for stored {@link KeySet}s.
 */
public class KeySetReader {
    /**
     * Loads a {@link KeySet} from an array of bytes.
     *
     * @throws CryptographicException if the encoded {@link KeySet} is malformed
     */
    public KeySet read(byte[] encoded) throws CryptographicException, IOException {
        return read(new ByteArrayInputStream(encoded));
    }

    /**
     * Loads a {@link KeySet} from an {@link java.io.InputStream}.
     */
    public KeySet read(InputStream input) throws CryptographicException, IOException {
        try {
            final KeySet keySet = new KeySet(new PGPSecretKeyRing(input, new JcaKeyFingerprintCalculator()));
            final MasterKey masterKey = keySet.getMasterKey();
            final SubKey subKey = keySet.getSubKey();

            final KeySignature masterSig = masterKey.signature;
            if (masterSig == null || !masterSig.verifyCertification(masterKey)) {
                throw new CryptographicException("Key set has no self-signed master key");
            }

            final KeySignature subSig = subKey.signature;
            if (subSig == null || !subSig.verifyCertification(subKey, masterKey)) {
                throw new CryptographicException("Key set has no valid subkey");
            }

            return keySet;
        } catch (PGPException e) {
            throw new CryptographicException(e);
        } finally {
            input.close();
        }
    }
}
