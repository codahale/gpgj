package com.codahale.gpgj;

import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.junit.Test;

import static org.fest.assertions.api.Assertions.assertThat;

@SuppressWarnings("deprecation")
public class CompressionAlgorithmTest {
    @Test
    public void noneHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(CompressionAlgorithm.NONE.value())
                .isEqualTo(CompressionAlgorithmTags.UNCOMPRESSED);
    }

    @Test
    public void noneIsHumanReadable() throws Exception {
        assertThat(CompressionAlgorithm.NONE.toString())
                .isEqualTo("None");
    }

    @Test
    public void zlibHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(CompressionAlgorithm.ZLIB.value())
                .isEqualTo(CompressionAlgorithmTags.ZLIB);
    }

    @Test
    public void zlibIsHumanReadable() throws Exception {
        assertThat(CompressionAlgorithm.ZLIB.toString())
                .isEqualTo("ZLIB");
    }

    @Test
    public void zipHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(CompressionAlgorithm.ZIP.value())
                .isEqualTo(CompressionAlgorithmTags.ZIP);
    }

    @Test
    public void zipIsHumanReadable() throws Exception {
        assertThat(CompressionAlgorithm.ZIP.toString())
                .isEqualTo("ZIP");
    }

    @Test
    public void bzip2HasTheSameValueAsTheBCTag() throws Exception {
        assertThat(CompressionAlgorithm.BZIP2.value())
                .isEqualTo(CompressionAlgorithmTags.BZIP2);
    }

    @Test
    public void bzip2IsHumanReadable() throws Exception {
        assertThat(CompressionAlgorithm.BZIP2.toString())
                .isEqualTo("BZIP2");
    }

    @Test
    public void usesZLIBByDefault() throws Exception {
        assertThat(CompressionAlgorithm.DEFAULT)
                .isEqualTo(CompressionAlgorithm.ZLIB);
    }
}
