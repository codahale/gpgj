package com.codahale.gpgj;

import org.junit.Before;
import org.junit.Test;

import java.io.FileInputStream;

import static org.fest.assertions.api.Assertions.assertThat;

public class KeySetTest extends BCTest {
    private KeySet keySet;

    @Before
    public void setUp() throws Exception {
        try (FileInputStream file = new FileInputStream("src/test/resources/secret-keyring.gpg")) {
            this.keySet = new KeySetReader().read(file);
        }
    }

    @Test
    public void hasAMasterKey() throws Exception {
        assertThat(keySet.getMasterKey().getKeyID())
                .isEqualTo(0x8C7035EF8838238CL);
    }

    @Test
    public void hasASubKey() throws Exception {
        assertThat(keySet.getSubKey().getKeyID())
                .isEqualTo(0xA3A5D038FF30574EL);
    }

    @Test
    public void isHumanReadable() throws Exception {
        assertThat(keySet.toString())
                .isEqualTo("[2048-RSA/8838238C, 2048-RSA/FF30574E]");
    }

    @Test
    public void hasAUserID() throws Exception {
        assertThat(keySet.getUserID())
                .isEqualTo("Sample Key <sample@wesabe.com>");
    }
}
