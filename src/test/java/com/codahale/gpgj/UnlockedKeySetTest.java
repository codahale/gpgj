package com.codahale.gpgj;

import org.junit.Before;
import org.junit.Test;

import java.io.FileInputStream;
import java.security.SecureRandom;

import static org.fest.assertions.api.Assertions.assertThat;
import static org.fest.assertions.api.Assertions.failBecauseExceptionWasNotThrown;

public class UnlockedKeySetTest extends BCTest {
    private UnlockedKeySet unlockedKeySet;

    @Before
    public void setUp() throws Exception {
        try (FileInputStream file = new FileInputStream("src/test/resources/secret-keyring.gpg")) {
            final KeySet keySet = new KeySetReader().read(file);
            this.unlockedKeySet = keySet.unlock("test".toCharArray());
        }
    }

    @Test
    public void hasAnUnlockedMasterKey() throws Exception {
        assertThat(unlockedKeySet.getUnlockedMasterKey().getKeyID())
                .isEqualTo(0x8C7035EF8838238CL);
    }

    @Test
    public void hasAnUnlockedSubKey() throws Exception {
        assertThat(unlockedKeySet.getUnlockedSubKey().getKeyID())
                .isEqualTo(0xA3A5D038FF30574EL);
    }

    @Test
    public void canReLockTheKeySetWithADifferentPassphrase() throws Exception {
        final KeySet newKeySet = unlockedKeySet.relock("test".toCharArray(), "yes".toCharArray(),
                                                       new SecureRandom());

        try {
            newKeySet.unlock("test".toCharArray());
            failBecauseExceptionWasNotThrown(CryptographicException.class);
        } catch (CryptographicException e) {
            assertThat(e.getMessage())
                    .isEqualTo("incorrect passphrase");
        }

        assertThat(newKeySet.unlock("yes".toCharArray()))
                .isNotNull();
    }
}
