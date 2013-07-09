package com.codahale.gpgj;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.junit.Test;

import java.security.SecureRandom;

import static org.fest.assertions.api.Assertions.assertThat;

public class DsaKeyGeneratorTest {
    private final SecureRandom random = new SecureRandom();

    @Test
    public void generatesDSAKeys() throws Exception {
        assertThat(DsaKeyGenerator.dsa1024().getAlgorithm())
                .isEqualTo(AsymmetricAlgorithm.DSA);
    }

    @Test
    public void generates1024bitKeys() throws Exception {
        final AsymmetricCipherKeyPair pair = DsaKeyGenerator.dsa1024().generate(random);

        assertThat(pair.getPrivate())
                .isInstanceOf(DSAPrivateKeyParameters.class);

        final DSAPrivateKeyParameters privateKeys = (DSAPrivateKeyParameters) pair.getPrivate();
        assertThat(privateKeys.getParameters().getP().toByteArray().length)
                .isEqualTo(129);
    }

    @Test
    public void generates2048bitKeys() throws Exception {
        final AsymmetricCipherKeyPair pair = DsaKeyGenerator.dsa2048().generate(random);

        assertThat(pair.getPrivate())
                .isInstanceOf(DSAPrivateKeyParameters.class);

        final DSAPrivateKeyParameters privateKeys = (DSAPrivateKeyParameters) pair.getPrivate();
        assertThat(privateKeys.getParameters().getP().toByteArray().length)
                .isIn(257);
    }

    @Test
    public void generates3072bitKeys() throws Exception {
        final AsymmetricCipherKeyPair pair = DsaKeyGenerator.dsa3072().generate(random);

        assertThat(pair.getPrivate())
                .isInstanceOf(DSAPrivateKeyParameters.class);

        final DSAPrivateKeyParameters privateKeys = (DSAPrivateKeyParameters) pair.getPrivate();
        assertThat(privateKeys.getParameters().getP().toByteArray().length)
                .isIn(385);
    }
}
