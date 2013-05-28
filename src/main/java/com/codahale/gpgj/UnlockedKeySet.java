package com.codahale.gpgj;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import java.security.SecureRandom;

/**
 * An unlocked {@link KeySet}.
 */
public class UnlockedKeySet extends KeySet {
    UnlockedKeySet(UnlockedMasterKey masterKey, UnlockedSubKey subKey) {
        super(masterKey, subKey);
    }

    /**
     * Returns the {@link UnlockedMasterKey}.
     */
    public UnlockedMasterKey getUnlockedMasterKey() {
        return (UnlockedMasterKey) getMasterKey();
    }

    /**
     * Returns the {@link UnlockedSubKey}.
     */
    public UnlockedSubKey getUnlockedSubKey() {
        return (UnlockedSubKey) getSubKey();
    }

    @Override
    public UnlockedKeySet unlock(char[] passphrase) throws CryptographicException {
        return this;
    }

    /**
     * Re-encrypts the key set with a new passphrase and returns it in locked
     * form.
     *
     * @param oldPassphrase the old passphrase
     * @param newPassphrase the new passphrase
     * @return {@code this}, re-encrypted with {@code newPassphrase}
     * @throws CryptographicException if {@code oldPassphrase} is incorrect
     */
    public KeySet relock(char[] oldPassphrase, char[] newPassphrase, SecureRandom random) throws CryptographicException {
        try {
            final PBESecretKeyDecryptor decryptor =
                    new JcePBESecretKeyDecryptorBuilder()
                            .build(oldPassphrase);
            final PBESecretKeyEncryptor encryptor =
                    new JcePBESecretKeyEncryptorBuilder(SymmetricAlgorithm.DEFAULT.value())
                            .setSecureRandom(random)
                            .build(newPassphrase);
            final PGPSecretKey masterSecretKey = PGPSecretKey.copyWithNewPassword(
                    getUnlockedMasterKey().getSecretKey(),
                    decryptor,
                    encryptor
            );
            final PGPSecretKey subSecretKey = PGPSecretKey.copyWithNewPassword(
                    getUnlockedSubKey().getSecretKey(),
                    decryptor,
                    encryptor
            );

            final MasterKey newMasterKey = new MasterKey(masterSecretKey);
            final SubKey newSubKey = new SubKey(subSecretKey, newMasterKey);

            return new KeySet(newMasterKey, newSubKey);
        } catch (PGPException e) {
            throw new CryptographicException(e);
        }
    }
}
