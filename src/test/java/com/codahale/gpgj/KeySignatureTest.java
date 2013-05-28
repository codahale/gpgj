package com.codahale.gpgj;

import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.fest.util.Dates;
import org.junit.Before;
import org.junit.Test;

import java.io.FileInputStream;
import java.util.Iterator;

import static org.fest.assertions.api.Assertions.assertThat;

public class KeySignatureTest extends BCTest {
    private KeySignature signature;

    @Before
    public void setUp() throws Exception {
        try (FileInputStream file = new FileInputStream("src/test/resources/secret-keyring.gpg")) {
            final PGPSecretKeyRing keyRing = new PGPSecretKeyRing(file, new JcaKeyFingerprintCalculator());
            final PGPSecretKey key = keyRing.getSecretKey(0x8C7035EF8838238CL);
            final Iterator<?> signatures = key.getPublicKey().getSignatures();
            this.signature = new KeySignature((PGPSignature) signatures.next());
        }
    }

    @Test
    public void hasASignatureType() throws Exception {
        assertThat(signature.getSignatureType())
                .isEqualTo(SignatureType.POSITIVE_CERTIFICATION);
    }

    @Test
    public void hasAKeyID() throws Exception {
        assertThat(signature.getKeyID()).isEqualTo(0x8C7035EF8838238CL);
    }

    @Test
    @SuppressWarnings("deprecation")
    public void hasAHashAlgorithm() throws Exception {
        assertThat(signature.getHashAlgorithm())
                .isEqualTo(HashAlgorithm.SHA_1);
    }

    @Test
    public void hasAKeyAlgorithm() throws Exception {
        assertThat(signature.getKeyAlgorithm())
                .isEqualTo(AsymmetricAlgorithm.RSA);
    }

    @Test
    public void hasACreationTimestamp() throws Exception {
        assertThat(signature.getCreatedAt())
                .withDateFormat(Dates.ISO_DATE_TIME_FORMAT)
                .isEqualTo("2009-07-09T09:22:03");
    }

    @Test
    public void hasKeyFlags() throws Exception {
        assertThat(signature.getKeyFlags())
                .containsOnly(KeyFlag.CERTIFICATION, KeyFlag.SIGNING);
    }

    @Test
    @SuppressWarnings("deprecation")
    public void hasPreferredSymmetricAlgorithms() throws Exception {
        assertThat(signature.getPreferredSymmetricAlgorithms())
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
        assertThat(signature.getPreferredCompressionAlgorithms())
                .containsExactly(
                        CompressionAlgorithm.ZLIB,
                        CompressionAlgorithm.BZIP2,
                        CompressionAlgorithm.ZIP
                );
    }

    @Test
    @SuppressWarnings("deprecation")
    public void hasPreferredHashAlgorithms() throws Exception {
        assertThat(signature.getPreferredHashAlgorithms())
                .containsExactly(
                        HashAlgorithm.SHA_1,
                        HashAlgorithm.SHA_256,
                        HashAlgorithm.RIPEMD_160
                );
    }
}
