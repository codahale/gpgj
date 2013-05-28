package com.codahale.gpgj;

import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;

/**
 * An unlocked {@link SubKey}.
 */
public class UnlockedSubKey extends SubKey {
    private final PGPPrivateKey privateKey;

    UnlockedSubKey(PGPSecretKey key, MasterKey masterKey, PGPPrivateKey privateKey) throws CryptographicException {
        super(key, masterKey);
        this.privateKey = privateKey;
    }

    @Override
    public UnlockedSubKey unlock(char[] passphrase) {
        return this;
    }

    PGPPrivateKey getPrivateKey() {
        return privateKey;
    }
}
