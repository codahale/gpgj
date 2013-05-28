package com.codahale.gpgj;

import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;

/**
* An unlocked {@link MasterKey}.
*/
public class UnlockedMasterKey extends MasterKey {
    private final PGPPrivateKey privateKey;

    UnlockedMasterKey(PGPSecretKey secretKey, PGPPrivateKey privateKey) throws CryptographicException {
        super(secretKey);
        this.privateKey = privateKey;
    }

    @Override
    public UnlockedMasterKey unlock(char[] passphrase) {
        return this;
    }

    PGPPrivateKey getPrivateKey() {
        return privateKey;
    }
}
