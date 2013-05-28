package com.codahale.gpgj;

/**
 * A locked key.
 *
 * @param <T> the unlocked key type
 */
public interface Locked<T> {
    /**
     * Given the key's passphrase, unlocks the secret key and returns an unlocked equivalent of
     * {@code this}.
     *
     * @param passphrase the key's passphrase
     * @return a unlocked equivalent of {@code this}
     * @throws CryptographicException if {@code passphrase} is incorrect
     */
    T unlock(char[] passphrase) throws CryptographicException;
}
