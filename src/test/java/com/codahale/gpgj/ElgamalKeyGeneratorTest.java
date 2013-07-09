package com.codahale.gpgj;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import org.junit.Test;

import java.security.SecureRandom;

import static org.fest.assertions.api.Assertions.assertThat;

public class ElgamalKeyGeneratorTest {
    private final SecureRandom random = new SecureRandom();

    @Test
    public void generatesElgamalKeys() throws Exception {
        assertThat(ElgamalKeyGenerator.elgamal1024().getAlgorithm())
                .isEqualTo(AsymmetricAlgorithm.ELGAMAL);
    }

    @Test
    public void generates1024bitKeys() throws Exception {
        final AsymmetricCipherKeyPair pair = ElgamalKeyGenerator.elgamal1024().generate(random);

        assertThat(pair.getPrivate())
                .isInstanceOf(ElGamalPrivateKeyParameters.class);

        final ElGamalPrivateKeyParameters privateKeys = (ElGamalPrivateKeyParameters) pair.getPrivate();
        assertThat(privateKeys.getParameters().getP().toByteArray().length)
                .isEqualTo(129);
    }

    @Test
    public void generates2048bitKeys() throws Exception {
        final AsymmetricCipherKeyPair pair = ElgamalKeyGenerator.elgamal2048().generate(random);

        assertThat(pair.getPrivate())
                .isInstanceOf(ElGamalPrivateKeyParameters.class);

        final ElGamalPrivateKeyParameters privateKeys = (ElGamalPrivateKeyParameters) pair
                .getPrivate();
        assertThat(privateKeys.getParameters().getP().toByteArray().length)
                .isEqualTo(257);
    }

    @Test
    public void generates4096bitKeys() throws Exception {
        final AsymmetricCipherKeyPair pair = ElgamalKeyGenerator.elgamal4096().generate(random);

        assertThat(pair.getPrivate())
                .isInstanceOf(ElGamalPrivateKeyParameters.class);

        final ElGamalPrivateKeyParameters privateKeys = (ElGamalPrivateKeyParameters) pair
                .getPrivate();
        assertThat(privateKeys.getParameters().getP().toByteArray().length)
                .isEqualTo(513);
    }
}
