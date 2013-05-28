package com.codahale.gpgj;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.junit.Test;

import static org.fest.assertions.api.Assertions.assertThat;

@SuppressWarnings("deprecation")
public class SymmetricAlgorithmTest {
    @Test
    public void plaintextHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(SymmetricAlgorithm.PLAINTEXT.value())
                .isEqualTo(SymmetricKeyAlgorithmTags.NULL);
    }

    @Test
    public void plaintextIsHumanReadable() throws Exception {
        assertThat(SymmetricAlgorithm.PLAINTEXT.toString()).isEqualTo("Plaintext");
    }

    @Test
    public void ideaHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(SymmetricAlgorithm.IDEA.value())
                .isEqualTo(SymmetricKeyAlgorithmTags.IDEA);
    }

    @Test
    public void ideaIsHumanReadable() throws Exception {
        assertThat(SymmetricAlgorithm.IDEA.toString())
                .isEqualTo("IDEA");
    }

    @Test
    public void tripleDESHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(SymmetricAlgorithm.TRIPLE_DES.value())
                .isEqualTo(SymmetricKeyAlgorithmTags.TRIPLE_DES);
    }

    @Test
    public void tripleDESIsHumanReadable() throws Exception {
        assertThat(SymmetricAlgorithm.TRIPLE_DES.toString())
                .isEqualTo("3DES");
    }

    @Test
    public void castHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(SymmetricAlgorithm.CAST_128.value())
                .isEqualTo(SymmetricKeyAlgorithmTags.CAST5);
    }

    @Test
    public void castIsHumanReadable() throws Exception {
        assertThat(SymmetricAlgorithm.CAST_128.toString())
                .isEqualTo("CAST-128");
    }

    @Test
    public void blowfishHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(SymmetricAlgorithm.BLOWFISH.value())
                .isEqualTo(SymmetricKeyAlgorithmTags.BLOWFISH);
    }

    @Test
    public void blowfishIsHumanReadable() throws Exception {
        assertThat(SymmetricAlgorithm.BLOWFISH.toString())
                .isEqualTo("Blowfish");
    }

    @Test
    public void saferHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(SymmetricAlgorithm.SAFER_SK.value())
                .isEqualTo(SymmetricKeyAlgorithmTags.SAFER);
    }

    @Test
    public void saferIsHumanReadable() throws Exception {
        assertThat(SymmetricAlgorithm.SAFER_SK.toString())
                .isEqualTo("SAFER-SK");
    }

    @Test
    public void desHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(SymmetricAlgorithm.DES.value())
                .isEqualTo(SymmetricKeyAlgorithmTags.DES);
    }

    @Test
    public void desIsHumanReadable() throws Exception {
        assertThat(SymmetricAlgorithm.DES.toString())
                .isEqualTo("DES");
    }

    @Test
    public void aes128HasTheSameValueAsTheBCTag() throws Exception {
        assertThat(SymmetricAlgorithm.AES_128.value())
                .isEqualTo(SymmetricKeyAlgorithmTags.AES_128);
    }

    @Test
    public void aes128IsHumanReadable() throws Exception {
        assertThat(SymmetricAlgorithm.AES_128.toString())
                .isEqualTo("AES-128");
    }

    @Test
    public void aes192HasTheSameValueAsTheBCTag() throws Exception {
        assertThat(SymmetricAlgorithm.AES_192.value())
                .isEqualTo(SymmetricKeyAlgorithmTags.AES_192);
    }

    @Test
    public void aes192IsHumanReadable() throws Exception {
        assertThat(SymmetricAlgorithm.AES_192.toString())
                .isEqualTo("AES-192");
    }

    @Test
    public void aes256HasTheSameValueAsTheBCTag() throws Exception {
        assertThat(SymmetricAlgorithm.AES_256.value())
                .isEqualTo(SymmetricKeyAlgorithmTags.AES_256);
    }

    @Test
    public void aes256IsHumanReadable() throws Exception {
        assertThat(SymmetricAlgorithm.AES_256.toString())
                .isEqualTo("AES-256");
    }

    @Test
    public void twofishHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(SymmetricAlgorithm.TWOFISH.value())
                .isEqualTo(SymmetricKeyAlgorithmTags.TWOFISH);
    }

    @Test
    public void twofishIsHumanReadable() throws Exception {
        assertThat(SymmetricAlgorithm.TWOFISH.toString())
                .isEqualTo("Twofish");
    }

    @Test
    public void defaultsToAES256() throws Exception {
        assertThat(SymmetricAlgorithm.DEFAULT)
                .isEqualTo(SymmetricAlgorithm.AES_256);
    }

    @Test
    public void acceptsAESUsage() throws Exception {
        assertThat(SymmetricAlgorithm.ACCEPTABLE_ALGORITHMS)
                .containsOnly(
                        SymmetricAlgorithm.AES_128,
                        SymmetricAlgorithm.AES_192,
                        SymmetricAlgorithm.AES_256
                );
    }
}
