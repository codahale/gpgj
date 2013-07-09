package com.codahale.gpgj;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.junit.Test;

import static org.fest.assertions.api.Assertions.assertThat;

@SuppressWarnings("deprecation")
public class AsymmetricAlgorithmTest {
    @Test
    public void rsaHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(AsymmetricAlgorithm.RSA.value())
                .isEqualTo(PublicKeyAlgorithmTags.RSA_GENERAL);
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
    public void rsaSIsNamedRSAS() throws Exception {
        assertThat(AsymmetricAlgorithm.RSA_S.getName())
                .isEqualTo("RSA(s)");
    }

    @Test
    public void ecdhHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(AsymmetricAlgorithm.ECDH.value())
                .isEqualTo(PublicKeyAlgorithmTags.EC);
    }

    @Test
    public void ecdhIsNamedECDH() throws Exception {
        assertThat(AsymmetricAlgorithm.ECDH.getName())
                .isEqualTo("ECDH");
    }

    @Test
    public void ecdsaHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(AsymmetricAlgorithm.ECDSA.value())
                .isEqualTo(PublicKeyAlgorithmTags.ECDSA);
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
    public void dhIsNamedDH() throws Exception {
        assertThat(AsymmetricAlgorithm.DH.getName())
                .isEqualTo("DH");
    }
}
