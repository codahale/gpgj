package com.codahale.gpgj;

import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.fest.util.Dates;
import org.junit.Before;
import org.junit.Test;

import java.io.FileInputStream;

import static org.fest.assertions.api.Assertions.assertThat;
import static org.fest.assertions.api.Assertions.failBecauseExceptionWasNotThrown;

public class MasterKeyTest extends BCTest {
    private MasterKey key;

    @Before
    public void setUp() throws Exception {
        try (FileInputStream file = new FileInputStream("src/test/resources/secret-keyring.gpg")) {
            final PGPSecretKeyRing keyRing = new PGPSecretKeyRing(file, new JcaKeyFingerprintCalculator());
            this.key = new MasterKey(keyRing.getSecretKey(0x8C7035EF8838238CL));
        }
    }

    @Test
    public void hasAnID() throws Exception {
        assertThat(key.getKeyID())
                .isEqualTo(0x8C7035EF8838238CL);
    }

    @Test
    public void hasAHumanReadableID() throws Exception {
        assertThat(key.getHumanKeyID())
                .isEqualTo("8838238C");
    }

    @Test
    public void hasUserIDs() throws Exception {
        assertThat(key.getUserID())
                .isEqualTo("Sample Key <sample@wesabe.com>");
        assertThat(key.getUserIDs())
                .containsExactly("Sample Key <sample@wesabe.com>");
    }

    @Test
    public void hasAnAlgorithm() throws Exception {
        assertThat(key.getAlgorithm())
                .isEqualTo(AsymmetricAlgorithm.RSA);
    }

    @Test
    public void hasASize() throws Exception {
        assertThat(key.getSize())
                .isEqualTo(2048);
    }

    @Test
    public void cannotEncryptData() throws Exception {
        assertThat(key.canEncrypt())
                .isFalse();
    }

    @Test
    public void canSignData() throws Exception {
        assertThat(key.canSign())
                .isTrue();
    }

    @Test
    public void hasACreationTimestamp() throws Exception {
        assertThat(key.getCreatedAt())
                .withDateFormat(Dates.ISO_DATE_TIME_FORMAT)
                .isEqualTo("2009-07-09T09:22:03Z");
    }

    @Test
    public void hasKeyFlags() throws Exception {
        assertThat(key.getKeyFlags())
                .containsOnly(KeyFlag.SIGNING, KeyFlag.CERTIFICATION);
    }

    @Test
    public void isHumanReadable() throws Exception {
        assertThat(key.toString())
                .isEqualTo("2048-RSA/8838238C");
    }

    @Test
    @SuppressWarnings("deprecation")
    public void hasPreferredSymmetricAlgorithms() throws Exception {
        assertThat(key.getPreferredSymmetricAlgorithms())
                .containsExactly(
                        SymmetricAlgorithm.AES_256,
                        SymmetricAlgorithm.AES_192,
                        SymmetricAlgorithm.AES_128,
                        SymmetricAlgorithm.CAST_128,
                        SymmetricAlgorithm.TRIPLE_DES,
                        SymmetricAlgorithm.IDEA
                );
    }

    @Test
    public void hasPreferredCompressionAlgorithms() throws Exception {
        assertThat(key.getPreferredCompressionAlgorithms())
                .containsExactly(
                        CompressionAlgorithm.ZLIB,
                        CompressionAlgorithm.BZIP2,
                        CompressionAlgorithm.ZIP
                );
    }

    @Test
    @SuppressWarnings("deprecation")
    public void itHasPreferredHashAlgorithms() throws Exception {
        assertThat(key.getPreferredHashAlgorithms())
                .containsExactly(
                        HashAlgorithm.SHA_1,
                        HashAlgorithm.SHA_256,
                        HashAlgorithm.RIPEMD_160
                );
    }

    @Test
    public void returnsAnUnlockedMasterKeyForTheCorrectPassphrase() throws Exception {
        assertThat(key.unlock("test".toCharArray()))
                .isNotNull();
    }

    @Test
    public void throwsACryptographicExceptionForTheIncorrectPassphrase() throws Exception {
        try {
            key.unlock("wonk".toCharArray());
            failBecauseExceptionWasNotThrown(CryptographicException.class);
        } catch (CryptographicException e) {
            assertThat(e.getMessage())
                    .isEqualTo("incorrect passphrase");
        }
    }
}
