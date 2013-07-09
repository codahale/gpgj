package com.codahale.gpgj;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import java.security.SecureRandom;

/**
 * A generator for master keys.
 *
 * @see ElgamalKeyGenerator
 * @see RsaKeyGenerator
 */
public interface SubKeyGenerator {
    /**
     * Given a PRNG, generates a key pair.
     *
     * @param random    a PRNG
     * @return a key pair
     */
    AsymmetricCipherKeyPair generate(SecureRandom random);

    /**
     * Returns the algorithm used to generate the key pair.
     */
    AsymmetricAlgorithm getAlgorithm();
}
