package com.codahale.gpgj;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.junit.Test;

import java.security.SecureRandom;

import static org.fest.assertions.api.Assertions.assertThat;

@SuppressWarnings("deprecation")
public class EcdhKeyGeneratorTest {
    private final SecureRandom random = new SecureRandom();

    @Test
    public void generatesECDHKeys() throws Exception {
        assertThat(EcdhKeyGenerator.ecdhP256().getAlgorithm())
                .isEqualTo(AsymmetricAlgorithm.ECDH);
    }

    @Test
    public void generates256bitKeys() throws Exception {
        final AsymmetricCipherKeyPair pair = EcdhKeyGenerator.ecdhP256().generate(random);

        assertThat(pair.getPrivate())
                .isInstanceOf(ECPrivateKeyParameters.class);

        final ECPrivateKeyParameters params = (ECPrivateKeyParameters) pair.getPrivate();
        assertThat(params.getParameters().getN().toByteArray().length)
                .isEqualTo(33);
    }

    @Test
    public void generates384bitKeys() throws Exception {
        final AsymmetricCipherKeyPair pair = EcdhKeyGenerator.ecdhP384().generate(random);

        assertThat(pair.getPrivate())
                .isInstanceOf(ECPrivateKeyParameters.class);

        final ECPrivateKeyParameters params = (ECPrivateKeyParameters) pair.getPrivate();
        assertThat(params.getParameters().getN().toByteArray().length)
                .isEqualTo(49);
    }

    @Test
    public void generates521bitKeys() throws Exception {
        final AsymmetricCipherKeyPair pair = EcdhKeyGenerator.ecdhP521().generate(random);

        assertThat(pair.getPrivate())
                .isInstanceOf(ECPrivateKeyParameters.class);

        final ECPrivateKeyParameters params = (ECPrivateKeyParameters) pair.getPrivate();
        assertThat(params.getParameters().getN().toByteArray().length)
                .isEqualTo(66);
    }
}
