package com.codahale.gpgj;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.junit.Test;

import java.security.SecureRandom;

import static org.fest.assertions.api.Assertions.assertThat;


@SuppressWarnings("deprecation")
public class EcdsaKeyGeneratorTest {
    private final SecureRandom random = new SecureRandom();

    @Test
    public void generatesECDSAKeys() throws Exception {
        assertThat(EcdsaKeyGenerator.ecdsaP256().getAlgorithm())
                .isEqualTo(AsymmetricAlgorithm.ECDSA);
    }

    @Test
    public void generates256bitKeys() throws Exception {
        final AsymmetricCipherKeyPair pair = EcdsaKeyGenerator.ecdsaP256().generate(random);

        assertThat(pair.getPrivate())
                .isInstanceOf(ECPrivateKeyParameters.class);

        final ECPrivateKeyParameters params = (ECPrivateKeyParameters) pair.getPrivate();
        assertThat(params.getParameters().getN().toByteArray().length)
                .isEqualTo(33);
    }

    @Test
    public void generates384bitKeys() throws Exception {
        final AsymmetricCipherKeyPair pair = EcdsaKeyGenerator.ecdsaP384().generate(random);

        assertThat(pair.getPrivate())
                .isInstanceOf(ECPrivateKeyParameters.class);

        final ECPrivateKeyParameters params = (ECPrivateKeyParameters) pair.getPrivate();
        assertThat(params.getParameters().getN().toByteArray().length)
                .isEqualTo(49);
    }

    @Test
    public void generates521bitKeys() throws Exception {
        final AsymmetricCipherKeyPair pair = EcdsaKeyGenerator.ecdsaP521().generate(random);

        assertThat(pair.getPrivate())
                .isInstanceOf(ECPrivateKeyParameters.class);

        final ECPrivateKeyParameters params = (ECPrivateKeyParameters) pair.getPrivate();
        assertThat(params.getParameters().getN().toByteArray().length)
                .isEqualTo(66);
    }
}
