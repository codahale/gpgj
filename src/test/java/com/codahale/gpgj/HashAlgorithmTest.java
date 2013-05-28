package com.codahale.gpgj;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.junit.Test;

import static org.fest.assertions.api.Assertions.assertThat;

@SuppressWarnings("deprecation")
public class HashAlgorithmTest {
    @Test
    public void md5HasTheSameValueAsTheBCTag() throws Exception {
        assertThat(HashAlgorithm.MD5.value())
                .isEqualTo(HashAlgorithmTags.MD5);
    }

    @Test
    public void md5IsHumanReadable() throws Exception {
        assertThat(HashAlgorithm.MD5.toString())
                .isEqualTo("MD5");
    }

    @Test
    public void sha1HasTheSameValueAsTheBCTag() throws Exception {
        assertThat(HashAlgorithm.SHA_1.value())
                .isEqualTo(HashAlgorithmTags.SHA1);
    }

    @Test
    public void sha1IsHumanReadable() throws Exception {
        assertThat(HashAlgorithm.SHA_1.toString())
                .isEqualTo("SHA-1");
    }

    @Test
    public void ripemd160HasTheSameValueAsTheBCTag() throws Exception {
        assertThat(HashAlgorithm.RIPEMD_160.value())
                .isEqualTo(HashAlgorithmTags.RIPEMD160);
    }

    @Test
    public void ripemd160IsHumanReadable() throws Exception {
        assertThat(HashAlgorithm.RIPEMD_160.toString())
                .isEqualTo("RIPEMD-160");
    }

    @Test
    public void doubleSHAHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(HashAlgorithm.DOUBLE_SHA.value())
                .isEqualTo(HashAlgorithmTags.DOUBLE_SHA);
    }

    @Test
    public void doubleSHAIsHumanReadable() throws Exception {
        assertThat(HashAlgorithm.DOUBLE_SHA.toString()).isEqualTo("2xSHA-1");
    }

    @Test
    public void md2HasTheSameValueAsTheBCTag() throws Exception {
        assertThat(HashAlgorithm.MD2.value())
                .isEqualTo(HashAlgorithmTags.MD2);
    }

    @Test
    public void md2IsHumanReadable() throws Exception {
        assertThat(HashAlgorithm.MD2.toString())
                .isEqualTo("MD2");
    }

    @Test
    public void tiger192HasTheSameValueAsTheBCTag() throws Exception {
        assertThat(HashAlgorithm.TIGER_192.value())
                .isEqualTo(HashAlgorithmTags.TIGER_192);
    }

    @Test
    public void tiger192IsHumanReadable() throws Exception {
        assertThat(HashAlgorithm.TIGER_192.toString())
                .isEqualTo("TIGER-192");
    }

    @Test
    public void haval5HasTheSameValueAsTheBCTag() throws Exception {
        assertThat(HashAlgorithm.HAVAL_5_160.value())
                .isEqualTo(HashAlgorithmTags.HAVAL_5_160);
    }

    @Test
    public void haval5IsHumanReadable() throws Exception {
        assertThat(HashAlgorithm.HAVAL_5_160.toString())
                .isEqualTo("HAVAL-5-160");
    }

    @Test
    public void sha224HasTheSameValueAsTheBCTag() throws Exception {
        assertThat(HashAlgorithm.SHA_224.value())
                .isEqualTo(HashAlgorithmTags.SHA224);
    }

    @Test
    public void sha224IsHumanReadable() throws Exception {
        assertThat(HashAlgorithm.SHA_224.toString())
                .isEqualTo("SHA-224");
    }

    @Test
    public void sha256HasTheSameValueAsTheBCTag() throws Exception {
        assertThat(HashAlgorithm.SHA_256.value())
                .isEqualTo(HashAlgorithmTags.SHA256);
    }

    @Test
    public void sha256IsHumanReadable() throws Exception {
        assertThat(HashAlgorithm.SHA_256.toString())
                .isEqualTo("SHA-256");
    }

    @Test
    public void sha384HasTheSameValueAsTheBCTag() throws Exception {
        assertThat(HashAlgorithm.SHA_384.value())
                .isEqualTo(HashAlgorithmTags.SHA384);
    }

    @Test
    public void sha384IsHumanReadable() throws Exception {
        assertThat(HashAlgorithm.SHA_384.toString())
                .isEqualTo("SHA-384");
    }

    @Test
    public void sha512HasTheSameValueAsTheBCTag() throws Exception {
        assertThat(HashAlgorithm.SHA_512.value())
                .isEqualTo(HashAlgorithmTags.SHA512);
    }

    @Test
    public void sha512IsHumanReadable() throws Exception {
        assertThat(HashAlgorithm.SHA_512.toString())
                .isEqualTo("SHA-512");
    }

    @Test
    public void defaultsToSHA_512() throws Exception {
        assertThat(HashAlgorithm.DEFAULT)
                .isEqualTo(HashAlgorithm.SHA_512);
    }

    @Test
    public void acceptsAllSHA2VariantsAndSHA1() throws Exception {
        assertThat(HashAlgorithm.ACCEPTABLE_ALGORITHMS)
                .containsOnly(
                        HashAlgorithm.SHA_1,
                        HashAlgorithm.SHA_224,
                        HashAlgorithm.SHA_256,
                        HashAlgorithm.SHA_384,
                        HashAlgorithm.SHA_512
                );
    }
}
