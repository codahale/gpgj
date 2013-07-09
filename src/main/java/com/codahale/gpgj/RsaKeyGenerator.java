package com.codahale.gpgj;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;

import java.security.SecureRandom;
import java.security.spec.RSAKeyGenParameterSpec;

/**
 * Generates RSA master keys and sub keys.
 *
 * @see <a href="http://en.wikipedia.org/wiki/RSA">Wikipedia</a>
 */
public class RsaKeyGenerator implements MasterKeyGenerator, SubKeyGenerator {
    /**
     * Returns a {@link RsaKeyGenerator} which generates 1024-bit master keys.
     */
    public static RsaKeyGenerator rsa1024() {
        return new RsaKeyGenerator(1024);
    }

    /**
     * Returns a {@link RsaKeyGenerator} which generates 2048-bit master keys.
     */
    public static RsaKeyGenerator rsa2048() {
        return new RsaKeyGenerator(2048);
    }

    /**
     * Returns a {@link RsaKeyGenerator} which generates 4096-bit master keys.
     */
    public static RsaKeyGenerator rsa4096() {
        return new RsaKeyGenerator(4096);
    }

    private final int size;

    public RsaKeyGenerator(int size) {
        this.size = size;
    }

    @Override
    public AsymmetricCipherKeyPair generate(SecureRandom random) {
        final RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
        generator.init(new RSAKeyGenerationParameters(RSAKeyGenParameterSpec.F4, random, size, 12));
        return generator.generateKeyPair();
    }

    @Override
    public AsymmetricAlgorithm getAlgorithm() {
        return AsymmetricAlgorithm.RSA;
    }
}
