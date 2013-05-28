package com.codahale.gpgj;

import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;

import static org.fest.assertions.api.Assertions.assertThat;

public class MessageReaderTest extends BCTest {
    private KeySet owner;
    private UnlockedKeySet recipient;
    private byte[] original;

    @Before
    public void setUp() throws Exception {
        try (FileInputStream keyRingFile = new FileInputStream("src/test/resources/secret-keyring.gpg")) {
            this.owner = new KeySetReader().read(keyRingFile);
        }

        try (FileInputStream anotherKeyRingFile = new FileInputStream("src/test/resources/another-secret-keyring.gpg")) {
            this.recipient = new KeySetReader().read(anotherKeyRingFile).unlock("test2".toCharArray());
        }

        final ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (FileInputStream input = new FileInputStream("src/test/resources/encrypted-and-signed.txt")) {
            byte[] b = new byte[4096];
            int r;
            while ((r = input.read(b)) >= 0) {
                output.write(b, 0, r);
            }
        }
        this.original = output.toByteArray();
    }

    @Test
    public void readsAnEncryptedMessage() throws Exception {
        final ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (FileInputStream input = new FileInputStream("src/test/resources/encrypted-and-signed.txt.gpg")) {
            byte[] b = new byte[4096];
            int r;
            while ((r = input.read(b)) >= 0) {
                output.write(b, 0, r);
            }
        }

        final MessageReader reader = new MessageReader(owner, recipient);
        final byte[] body = reader.read(output.toByteArray());

        assertThat(body)
                .isEqualTo(original);
    }
}
