package com.codahale.gpgj;

import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.fest.util.Dates;
import org.junit.Before;
import org.junit.Test;

import java.io.FileInputStream;

import static org.fest.assertions.api.Assertions.assertThat;

public class SubKeyTest extends BCTest {
    private SubKey key;

    @Before
    public void setUp() throws Exception {
        try (FileInputStream file = new FileInputStream("src/test/resources/secret-keyring.gpg")) {
            final PGPSecretKeyRing keyRing = new PGPSecretKeyRing(file, new JcaKeyFingerprintCalculator());
            final MasterKey masterKey = new MasterKey(keyRing.getSecretKey(0x8C7035EF8838238CL));
            this.key = new SubKey(keyRing.getSecretKey(0xA3A5D038FF30574EL), masterKey);
        }
    }

    @Test
    public void hasAnID() throws Exception {
        assertThat(key.getKeyID())
                .isEqualTo(0xA3A5D038FF30574EL);
    }

    @Test
    public void hasAMasterKey() throws Exception {
        assertThat(key.getMasterKey().getKeyID())
                .isEqualTo(0x8C7035EF8838238CL);
    }

    @Test
    public void hasAUserID() throws Exception {
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
    public void canEncryptData() throws Exception {
        assertThat(key.canEncrypt())
                .isTrue();
    }

    @Test
    public void cannotSignData() throws Exception {
        assertThat(key.canSign())
                .isFalse();
    }

    @Test
    public void hasACreationTimestamp() throws Exception {
        assertThat(key.getCreatedAt())
                .withDateFormat(Dates.ISO_DATE_TIME_FORMAT)
                .isEqualTo("2009-07-09T09:23:05");
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
    public void hasPreferredHashAlgorithms() throws Exception {
        assertThat(key.getPreferredHashAlgorithms())
                .containsExactly(
                        HashAlgorithm.SHA_1,
                        HashAlgorithm.SHA_256,
                        HashAlgorithm.RIPEMD_160
                );
    }
}
