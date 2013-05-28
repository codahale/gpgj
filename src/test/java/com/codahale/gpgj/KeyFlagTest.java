package com.codahale.gpgj;

import org.junit.Test;

import static org.fest.assertions.api.Assertions.assertThat;

public class KeyFlagTest {
    @Test
    public void certificationHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(KeyFlag.CERTIFICATION.value())
                .isEqualTo(0x01);
    }

    @Test
    public void signingHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(KeyFlag.SIGNING.value())
                .isEqualTo(0x02);
    }

    @Test
    public void encryptionHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(KeyFlag.ENCRYPTION.value())
                .isEqualTo(0x0C);
    }

    @Test
    public void splitHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(KeyFlag.SPLIT.value())
                .isEqualTo(0x10);
    }

    @Test
    public void authenticationHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(KeyFlag.AUTHENTICATION.value())
                .isEqualTo(0x20);
    }

    @Test
    public void sharedHasTheSameValueAsTheBCTag() throws Exception {
        assertThat(KeyFlag.SHARED.value())
                .isEqualTo(0x80);
    }

    @Test
    public void defaultMasterKeysCanSignBeSplitAndCanAuthenticate() throws Exception {
        assertThat(KeyFlag.MASTER_KEY_DEFAULTS)
                .containsOnly(KeyFlag.AUTHENTICATION, KeyFlag.SIGNING, KeyFlag.SPLIT);
    }

    @Test
    public void defaultSubKeysCanSignBeSplitAndCanAuthenticate() throws Exception {
        assertThat(KeyFlag.SUB_KEY_DEFAULTS)
                .containsOnly(KeyFlag.ENCRYPTION, KeyFlag.SPLIT);
    }
}
