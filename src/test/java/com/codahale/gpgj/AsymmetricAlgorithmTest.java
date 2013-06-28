package com.codahale.gpgj;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.crypto.generators.DSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.ElGamalKeyPairGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.DSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.ElGamalKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.fest.assertions.api.Assertions.assertThat;
import static org.fest.assertions.api.Assertions.failBecauseExceptionWasNotThrown;
import static org.mockito.Mockito.mock;

@SuppressWarnings("deprecation")
public class AsymmetricAlgorithmTest {
    @Test
    public void rsaHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(AsymmetricAlgorithm.RSA.value())
                .isEqualTo(PublicKeyAlgorithmTags.RSA_GENERAL);
    }

    @Test
    public void rsaCanGenerateKeys() throws Exception {
        assertThat(AsymmetricAlgorithm.RSA.getGenerator())
                .isInstanceOf(RSAKeyPairGenerator.class);
    }

    @Test
    public void rsaHasADefaultSizeOf2048Bits() throws Exception {
        final SecureRandom random = mock(SecureRandom.class);
        final RSAKeyGenerationParameters spec =
                (RSAKeyGenerationParameters) AsymmetricAlgorithm.RSA.getParameters(random);
        assertThat(spec.getStrength())
                .isEqualTo(2048);
    }

    @Test
    public void rsaUsesASmallExponent() throws Exception {
        final SecureRandom random = mock(SecureRandom.class);
        final RSAKeyGenerationParameters spec =
                (RSAKeyGenerationParameters) AsymmetricAlgorithm.RSA.getParameters(random);
        assertThat(spec.getPublicExponent())
                .isEqualTo(new BigInteger("65537"));
    }

    @Test
    public void rsaReusesThePRNG() throws Exception {
        final SecureRandom random = mock(SecureRandom.class);
        final RSAKeyGenerationParameters spec =
                (RSAKeyGenerationParameters) AsymmetricAlgorithm.RSA.getParameters(random);
        assertThat(spec.getRandom())
                .isEqualTo(random);
    }

    @Test
    public void rsaIsNamedRSA() throws Exception {
        assertThat(AsymmetricAlgorithm.RSA.getName())
                .isEqualTo("RSA");
        assertThat(AsymmetricAlgorithm.RSA.toString())
                .isEqualTo("RSA");
    }

    @Test
    public void elgamalHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(AsymmetricAlgorithm.ELGAMAL.value())
                .isEqualTo(PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT);
    }

    @Test
    public void elgamalCanGenerateKeys() throws Exception {
        assertThat(AsymmetricAlgorithm.ELGAMAL.getGenerator())
                .isInstanceOf(ElGamalKeyPairGenerator.class);
    }

    @Test
    public void elgamalUsesFastParameters() throws Exception {
        final SecureRandom random = mock(SecureRandom.class);
        final ElGamalKeyGenerationParameters spec =
                (ElGamalKeyGenerationParameters) AsymmetricAlgorithm.ELGAMAL.getParameters(random);
        assertThat(spec.getParameters())
                .isInstanceOf(FastElgamalParameters.class);
    }

    @Test
    public void elgamalReusesThePRNG() throws Exception {
        final SecureRandom random = mock(SecureRandom.class);
        final ElGamalKeyGenerationParameters spec =
                (ElGamalKeyGenerationParameters) AsymmetricAlgorithm.ELGAMAL.getParameters(random);
        assertThat(spec.getRandom())
                .isEqualTo(random);
    }

    @Test
    public void elgamalIsNamedElgamal() throws Exception {
        assertThat(AsymmetricAlgorithm.ELGAMAL.getName())
                .isEqualTo("Elgamal");
    }

    @Test
    public void dsaHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(AsymmetricAlgorithm.DSA.value())
                .isEqualTo(PublicKeyAlgorithmTags.DSA);
    }

    @Test
    public void dsaCanGenerateKeys() throws Exception {
        assertThat(AsymmetricAlgorithm.DSA.getGenerator())
                .isInstanceOf(DSAKeyPairGenerator.class);
    }

    @Test
    public void dsaUsesFastParameters() throws Exception {
        final SecureRandom random = mock(SecureRandom.class);
        final DSAKeyGenerationParameters spec =
                (DSAKeyGenerationParameters) AsymmetricAlgorithm.DSA.getParameters(random);
        assertThat(spec.getParameters())
                .isInstanceOf(FastDSAParameters.class);
    }

    @Test
    public void dsaReusesThePRNG() throws Exception {
        final SecureRandom random = mock(SecureRandom.class);
        final DSAKeyGenerationParameters spec =
                (DSAKeyGenerationParameters) AsymmetricAlgorithm.DSA.getParameters(random);
        assertThat(spec.getRandom())
                .isEqualTo(random);
    }

    @Test
    public void dsaIsNamedDSA() throws Exception {
        assertThat(AsymmetricAlgorithm.DSA.getName())
                .isEqualTo("DSA");
    }

    @Test
    public void rsaEHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(AsymmetricAlgorithm.RSA_E.value())
                .isEqualTo(PublicKeyAlgorithmTags.RSA_ENCRYPT);
    }

    @Test
    public void rsaEProhibitsKeyGeneration() throws Exception {
        try {
            AsymmetricAlgorithm.RSA_E.getGenerator();
            failBecauseExceptionWasNotThrown(UnsupportedOperationException.class);
        } catch (UnsupportedOperationException e) {
            assertThat(e.getMessage()).isEqualTo("RSA(e) keys cannot be generated");
        }
    }

    @Test
    public void rsaEIsNamedRSAE() throws Exception {
        assertThat(AsymmetricAlgorithm.RSA_E.getName())
                .isEqualTo("RSA(e)");
    }

    @Test
    public void rsaSHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(AsymmetricAlgorithm.RSA_S.value())
                .isEqualTo(PublicKeyAlgorithmTags.RSA_SIGN);
    }

    @Test
    public void rsaSProhibitsKeyGeneration() throws Exception {
        try {
            AsymmetricAlgorithm.RSA_S.getGenerator();
            failBecauseExceptionWasNotThrown(UnsupportedOperationException.class);
        } catch (UnsupportedOperationException e) {
            assertThat(e.getMessage()).isEqualTo("RSA(s) keys cannot be generated");
        }
    }

    @Test
    public void rsaSIsNamedRSAS() throws Exception {
        assertThat(AsymmetricAlgorithm.RSA_S.getName())
                .isEqualTo("RSA(s)");
    }

    @Test
    public void ecHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(AsymmetricAlgorithm.EC.value())
                .isEqualTo(PublicKeyAlgorithmTags.EC);
    }

    @Test
    public void ecProhibitsKeyGeneration() throws Exception {
        try {
            AsymmetricAlgorithm.EC.getGenerator();
            failBecauseExceptionWasNotThrown(UnsupportedOperationException.class);
        } catch (UnsupportedOperationException e) {
            assertThat(e.getMessage()).isEqualTo("EC keys cannot be generated");
        }
    }

    @Test
    public void ecIsNamedEC() throws Exception {
        assertThat(AsymmetricAlgorithm.EC.getName())
                .isEqualTo("EC");
    }

    @Test
    public void ecdsaHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(AsymmetricAlgorithm.ECDSA.value())
                .isEqualTo(PublicKeyAlgorithmTags.ECDSA);
    }

    @Test
    public void ecdsaProhibitsKeyGeneration() throws Exception {
        try {
            AsymmetricAlgorithm.ECDSA.getGenerator();
            failBecauseExceptionWasNotThrown(UnsupportedOperationException.class);
        } catch (UnsupportedOperationException e) {
            assertThat(e.getMessage()).isEqualTo("ECDSA keys cannot be generated");
        }
    }

    @Test
    public void ecdsaIsNamedECDSA() throws Exception {
        assertThat(AsymmetricAlgorithm.ECDSA.getName())
                .isEqualTo("ECDSA");
    }

    @Test
    public void elgamalGHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(AsymmetricAlgorithm.ELGAMAL_G.value())
                .isEqualTo(PublicKeyAlgorithmTags.ELGAMAL_GENERAL);
    }

    @Test
    public void elgamalGProhibitsKeyGeneration() throws Exception {
        try {
            AsymmetricAlgorithm.ELGAMAL_G.getGenerator();
            failBecauseExceptionWasNotThrown(UnsupportedOperationException.class);
        } catch (UnsupportedOperationException e) {
            assertThat(e.getMessage()).isEqualTo("Elgamal(g) keys cannot be generated");
        }
    }

    @Test
    public void elgamalGIsNamedElgamalG() throws Exception {
        assertThat(AsymmetricAlgorithm.ELGAMAL_G.getName())
                .isEqualTo("Elgamal(g)");
    }

    @Test
    public void dhHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(AsymmetricAlgorithm.DH.value())
                .isEqualTo(PublicKeyAlgorithmTags.DIFFIE_HELLMAN);
    }

    @Test
    public void dhProhibitsKeyGeneration() throws Exception {
        try {
            AsymmetricAlgorithm.DH.getGenerator();
            failBecauseExceptionWasNotThrown(UnsupportedOperationException.class);
        } catch (UnsupportedOperationException e) {
            assertThat(e.getMessage()).isEqualTo("DH keys cannot be generated");
        }
    }

    @Test
    public void dhIsNamedDH() throws Exception {
        assertThat(AsymmetricAlgorithm.DH.getName())
                .isEqualTo("DH");
    }

    @Test
    public void encryptsUsingRSAByDefault() throws Exception {
        assertThat(AsymmetricAlgorithm.ENCRYPTION_DEFAULT)
                .isEqualTo(AsymmetricAlgorithm.RSA);
    }

    @Test
    public void signsUsingRSAByDefault() throws Exception {
        assertThat(AsymmetricAlgorithm.SIGNING_DEFAULT)
                .isEqualTo(AsymmetricAlgorithm.RSA);
    }
}
