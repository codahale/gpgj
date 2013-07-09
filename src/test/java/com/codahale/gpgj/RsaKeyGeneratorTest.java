package com.codahale.gpgj;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.junit.Test;

import java.security.SecureRandom;

import static org.fest.assertions.api.Assertions.assertThat;

public class RsaKeyGeneratorTest {
    private final SecureRandom random = new SecureRandom();

    @Test
    public void generatesRSAKeys() throws Exception {
        assertThat(RsaKeyGenerator.rsa1024().getAlgorithm())
                .isEqualTo(AsymmetricAlgorithm.RSA);
    }

    @Test
    public void generates1024bitKeys() throws Exception {
        final AsymmetricCipherKeyPair pair = RsaKeyGenerator.rsa1024().generate(random);

        assertThat(pair.getPrivate())
                .isInstanceOf(RSAPrivateCrtKeyParameters.class);

        final RSAPrivateCrtKeyParameters privateKey = (RSAPrivateCrtKeyParameters) pair.getPrivate();
        assertThat(privateKey.getModulus().toByteArray().length)
                .isEqualTo(129);
    }

    @Test
    public void generates2048bitKeys() throws Exception {
        final AsymmetricCipherKeyPair pair = RsaKeyGenerator.rsa2048().generate(random);

        assertThat(pair.getPrivate())
                .isInstanceOf(RSAPrivateCrtKeyParameters.class);

        final RSAPrivateCrtKeyParameters privateKey = (RSAPrivateCrtKeyParameters) pair
                .getPrivate();
        assertThat(privateKey.getModulus().toByteArray().length)
                .isEqualTo(257);
    }

    @Test
    public void generates4096bitKeys() throws Exception {
        final AsymmetricCipherKeyPair pair = RsaKeyGenerator.rsa4096().generate(random);

        assertThat(pair.getPrivate())
                .isInstanceOf(RSAPrivateCrtKeyParameters.class);

        final RSAPrivateCrtKeyParameters privateKey = (RSAPrivateCrtKeyParameters) pair
                .getPrivate();
        assertThat(privateKey.getModulus().toByteArray().length)
                .isEqualTo(513);
    }
}
