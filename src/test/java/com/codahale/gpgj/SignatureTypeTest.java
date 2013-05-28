package com.codahale.gpgj;

import org.bouncycastle.openpgp.PGPSignature;
import org.junit.Test;

import static org.fest.assertions.api.Assertions.assertThat;

public class SignatureTypeTest {
    @Test
    public void binaryDocumentHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(SignatureType.BINARY_DOCUMENT.value())
                .isEqualTo(PGPSignature.BINARY_DOCUMENT);
    }

    @Test
    public void binaryDocumentIsHumanReadable() throws Exception {
        assertThat(SignatureType.BINARY_DOCUMENT.toString())
                .isEqualTo("binary document");
    }

    @Test
    public void textDocumentHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(SignatureType.TEXT_DOCUMENT.value())
                .isEqualTo(PGPSignature.CANONICAL_TEXT_DOCUMENT);
    }

    @Test
    public void textDocumentIsHumanReadable() throws Exception {
        assertThat(SignatureType.TEXT_DOCUMENT.toString())
                .isEqualTo("text document");
    }

    @Test
    public void standaloneHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(SignatureType.STANDALONE.value())
                .isEqualTo(PGPSignature.STAND_ALONE);
    }

    @Test
    public void standaloneIsHumanReadable() throws Exception {
        assertThat(SignatureType.STANDALONE.toString())
                .isEqualTo("standalone");
    }

    @Test
    public void defaultCertificationHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(SignatureType.DEFAULT_CERTIFICATION.value())
                .isEqualTo(PGPSignature.DEFAULT_CERTIFICATION);
    }

    @Test
    public void defaultCertificationIsHumanReadable() throws Exception {
        assertThat(SignatureType.DEFAULT_CERTIFICATION.toString())
                .isEqualTo("default certification");
    }

    @Test
    public void noCertificationHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(SignatureType.NO_CERTIFICATION.value())
                .isEqualTo(PGPSignature.NO_CERTIFICATION);
    }

    @Test
    public void noCertificationIsHumanReadable() throws Exception {
        assertThat(SignatureType.NO_CERTIFICATION.toString())
                .isEqualTo("no certification");
    }

    @Test
    public void casualCertificationHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(SignatureType.CASUAL_CERTIFICATION.value())
                .isEqualTo(PGPSignature.CASUAL_CERTIFICATION);
    }

    @Test
    public void certificationIsHumanReadable() throws Exception {
        assertThat(SignatureType.CASUAL_CERTIFICATION.toString())
                .isEqualTo("casual certification");
    }

    @Test
    public void positiveCertificationHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(SignatureType.POSITIVE_CERTIFICATION.value())
                .isEqualTo(PGPSignature.POSITIVE_CERTIFICATION);
    }

    @Test
    public void positiveCertificationIsHumanReadable() throws Exception {
        assertThat(SignatureType.POSITIVE_CERTIFICATION.toString())
                .isEqualTo("positive certification");
    }

    @Test
    public void subKeyBindingHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(SignatureType.SUBKEY_BINDING.value())
                .isEqualTo(PGPSignature.SUBKEY_BINDING);
    }

    @Test
    public void subKeyBindingIsHumanReadable() throws Exception {
        assertThat(SignatureType.SUBKEY_BINDING.toString())
                .isEqualTo("subkey binding");
    }

    @Test
    public void primaryKeyBindingHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(SignatureType.PRIMARY_KEY_BINDING.value())
                .isEqualTo(PGPSignature.PRIMARYKEY_BINDING);
    }

    @Test
    public void primaryKeyBindingIsHumanReadable() throws Exception {
        assertThat(SignatureType.PRIMARY_KEY_BINDING.toString())
                .isEqualTo("primary key binding");
    }

    @Test
    public void directKeyHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(SignatureType.DIRECT_KEY.value())
                .isEqualTo(PGPSignature.DIRECT_KEY);
    }

    @Test
    public void directKeyIsHumanReadable() throws Exception {
        assertThat(SignatureType.DIRECT_KEY.toString())
                .isEqualTo("direct key");
    }

    @Test
    public void keyRevocationHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(SignatureType.KEY_REVOCATION.value())
                .isEqualTo(PGPSignature.KEY_REVOCATION);
    }

    @Test
    public void keyRevocationIsHumanReadable() throws Exception {
        assertThat(SignatureType.KEY_REVOCATION.toString())
                .isEqualTo("key revocation");
    }

    @Test
    public void subKeyRevocationHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(SignatureType.SUBKEY_REVOCATION.value())
                .isEqualTo(PGPSignature.SUBKEY_REVOCATION);
    }

    @Test
    public void subKeyRevocationIsHumanReadable() throws Exception {
        assertThat(SignatureType.SUBKEY_REVOCATION.toString())
                .isEqualTo("subkey revocation");
    }

    @Test
    public void certRevocationHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(SignatureType.CERTIFICATION_REVOCATION.value())
                .isEqualTo(PGPSignature.CERTIFICATION_REVOCATION);
    }

    @Test
    public void certRevocationIsHumanReadable() throws Exception {
        assertThat(SignatureType.CERTIFICATION_REVOCATION.toString())
                .isEqualTo("certificate revocation");
    }

    @Test
    public void timestampHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(SignatureType.TIMESTAMP.value())
                .isEqualTo(PGPSignature.TIMESTAMP);
    }

    @Test
    public void timestampIsHumanReadable() throws Exception {
        assertThat(SignatureType.TIMESTAMP.toString())
                .isEqualTo("timestamp");
    }

    @Test
    public void thirdPartyHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(SignatureType.THIRD_PARTY.value())
                .isEqualTo(0x50);
    }

    @Test
    public void thirdPartyIsHumanReadable() throws Exception {
        assertThat(SignatureType.THIRD_PARTY.toString())
                .isEqualTo("third-party confirmation");
    }
}
