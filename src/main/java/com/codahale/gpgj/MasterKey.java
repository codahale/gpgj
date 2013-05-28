package com.codahale.gpgj;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

/**
* A PGP master key, used for signing and verifying data. <b>Must</b> be a self-certified key.
*/
public class MasterKey extends AbstractKey implements Locked<UnlockedMasterKey> {
    MasterKey(PGPSecretKey secretKey) {
        super(secretKey, secretKey, SignatureType.POSITIVE_CERTIFICATION);
    }

    @Override
    public UnlockedMasterKey unlock(char[] passphrase) throws CryptographicException {
        try {
            final PBESecretKeyDecryptor decryptor =
                    new JcePBESecretKeyDecryptorBuilder().build(passphrase);
            final PGPPrivateKey privateKey = secretKey.extractPrivateKey(decryptor);
            return new UnlockedMasterKey(secretKey, privateKey);
        } catch (PGPException e) {
            throw new CryptographicException("Incorrect passphrase", e);
        }
    }
}
