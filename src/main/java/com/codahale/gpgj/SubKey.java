package com.codahale.gpgj;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import java.util.List;

/**
 * A PGP subkey, used for encrypting and decrypting data. <b>Must</b> be
 * certified by a {@link MasterKey}.
 */
public class SubKey extends AbstractKey implements Locked<UnlockedSubKey> {
    private final MasterKey masterKey;

    SubKey(PGPSecretKey key, MasterKey masterKey) {
        super(key, masterKey.getSecretKey(), SignatureType.SUBKEY_BINDING);
        this.masterKey = masterKey;
    }

    @Override
    public String getUserID() {
        return masterKey.getUserID();
    }

    @Override
    public List<String> getUserIDs() {
        return masterKey.getUserIDs();
    }

    @Override
    public List<CompressionAlgorithm> getPreferredCompressionAlgorithms() {
        return masterKey.getPreferredCompressionAlgorithms();
    }

    @Override
    public List<HashAlgorithm> getPreferredHashAlgorithms() {
        return masterKey.getPreferredHashAlgorithms();
    }

    @Override
    public List<SymmetricAlgorithm> getPreferredSymmetricAlgorithms() {
        return masterKey.getPreferredSymmetricAlgorithms();
    }

    /**
     * Returns the paired {@link MasterKey}.
     */
    public MasterKey getMasterKey() {
        return masterKey;
    }

    @Override
    public UnlockedSubKey unlock(char[] passphrase) throws CryptographicException {
        try {
            final PBESecretKeyDecryptor decryptor =
                    new JcePBESecretKeyDecryptorBuilder().build(passphrase);
            final PGPPrivateKey privateKey = secretKey.extractPrivateKey(decryptor);
            return new UnlockedSubKey(secretKey, masterKey, privateKey);
        } catch (PGPException e) {
            throw new CryptographicException("Incorrect passphrase");
        }
    }
}
