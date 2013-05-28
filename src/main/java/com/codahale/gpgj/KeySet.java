package com.codahale.gpgj;

import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

import java.util.List;

/**
 * A {@link MasterKey} and {@link SubKey} pair.
 */
public class KeySet implements Locked<UnlockedKeySet> {
    private final MasterKey masterKey;
    private final SubKey subKey;

    KeySet(PGPSecretKeyRing keyRing) throws CryptographicException {
        final List<PGPSecretKey> secretKeys = Iterators.toList(keyRing.getSecretKeys());
        this.masterKey = new MasterKey(secretKeys.get(0));
        this.subKey = new SubKey(secretKeys.get(1), masterKey);
    }

    KeySet(MasterKey masterKey, SubKey subKey) {
        this.masterKey = masterKey;
        this.subKey = subKey;
    }

    /**
     * Returns the key set's {@link MasterKey}.
     */
    public MasterKey getMasterKey() {
        return masterKey;
    }

    /**
     * Returns the key set's {@link SubKey}.
     */
    public SubKey getSubKey() {
        return subKey;
    }

    /**
     * Returns the key set's user ID.
     */
    public String getUserID() {
        return masterKey.getUserID();
    }

    @Override
    public String toString() {
        return String.format("[%s, %s]", masterKey, subKey);
    }

    @Override
    public UnlockedKeySet unlock(char[] passphrase) throws CryptographicException {
        final UnlockedMasterKey unlockedMasterKey = masterKey.unlock(passphrase);
        final UnlockedSubKey unlockedSubKey = subKey.unlock(passphrase);
        return new UnlockedKeySet(unlockedMasterKey, unlockedSubKey);
    }
}
