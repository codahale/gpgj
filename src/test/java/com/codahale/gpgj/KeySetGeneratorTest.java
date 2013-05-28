package com.codahale.gpgj;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.fest.assertions.api.Assertions.assertThat;

public class KeySetGeneratorTest extends BCTest {
    private static ExecutorService THREAD_POOL;
    private static KeySet KEYSET;

    @BeforeClass
    public static void setUp() throws Exception {
        THREAD_POOL = Executors.newFixedThreadPool(8);
        final KeySetGenerator generator = new KeySetGenerator(new SecureRandom(), THREAD_POOL);
        KEYSET = generator.generate("Sample User <sample@example.com", "hello there".toCharArray());
    }

    @AfterClass
    public static void tearDown() throws Exception {
        THREAD_POOL.shutdown();
    }

    @Test
    public void hasAMasterKeyWithTheGivenUserID() throws Exception {
        assertThat(KEYSET.getMasterKey().getUserID())
                .isEqualTo("Sample User <sample@example.com");
    }

    @Test
    public void hasAMasterKeyOfTheDefaultType() throws Exception {
        assertThat(KEYSET.getMasterKey().getAlgorithm())
                .isEqualTo(AsymmetricAlgorithm.SIGNING_DEFAULT);
    }

    @Test
    public void hasAMasterKeyWhichCannotEncrypt() throws Exception {
        assertThat(KEYSET.getMasterKey().canEncrypt())
                .isFalse();
    }

    @Test
    public void hasAMasterKeyWhichCanSign() throws Exception {
        assertThat(KEYSET.getMasterKey().canSign())
                .isTrue();
    }

    @Test
    public void hasAMasterKeyWhichPrefersStrongEncryptionAlgorithms() throws Exception {
        assertThat(KEYSET.getMasterKey().getPreferredSymmetricAlgorithms())
                .containsAll(SymmetricAlgorithm.ACCEPTABLE_ALGORITHMS);
    }

    @Test
    public void hasAMasterKeyWhichPrefersStrongHashAlgorithms() throws Exception {
        assertThat(KEYSET.getMasterKey().getPreferredHashAlgorithms())
                .containsAll(HashAlgorithm.ACCEPTABLE_ALGORITHMS);
    }

    @Test
    public void hasAMasterKeyWhichPrefersCompressionAlgorithms() throws Exception {
        assertThat(KEYSET.getMasterKey().getPreferredCompressionAlgorithms())
                .containsOnly(
                        CompressionAlgorithm.BZIP2,
                        CompressionAlgorithm.ZLIB,
                        CompressionAlgorithm.ZIP
                );
    }

    @Test
    public void hasAMasterKeyWhichCanSignBeSplitAndAuthenticate() throws Exception {
        assertThat(KEYSET.getMasterKey().getKeyFlags())
                .containsOnly(
                        KeyFlag.AUTHENTICATION,
                        KeyFlag.SIGNING,
                        KeyFlag.SPLIT
                );
    }

    @Test
    public void hasASubKeyWithTheGivenUserID() throws Exception {
        assertThat(KEYSET.getSubKey().getUserID())
                .isEqualTo("Sample User <sample@example.com");
    }

    @Test
    public void hasASubKeyOfTheDefaultType() throws Exception {
        assertThat(KEYSET.getSubKey().getAlgorithm())
                .isEqualTo(AsymmetricAlgorithm.ENCRYPTION_DEFAULT);
    }

    @Test
    public void hasASubKeyWhichCanEncrypt() throws Exception {
        assertThat(KEYSET.getSubKey().canEncrypt())
                .isTrue();
    }

    @Test
    public void hasASubKeyWhichCannotSign() throws Exception {
        assertThat(KEYSET.getSubKey().canSign())
                .isFalse();
    }

    @Test
    public void hasASubKeyWhichCanEncryptAndBeSplit() throws Exception {
        assertThat(KEYSET.getSubKey().getKeyFlags())
                .containsOnly(
                        KeyFlag.ENCRYPTION,
                        KeyFlag.SPLIT
                );
    }
}
