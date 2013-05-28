package com.codahale.gpgj;

import org.junit.Before;
import org.junit.Test;

import java.io.FileInputStream;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import static org.fest.assertions.api.Assertions.assertThat;

public class MessageWriterTest extends BCTest {
    private UnlockedKeySet owner;
    private UnlockedKeySet recipient;
    private byte[] original;

    @Before
    public void setUp() throws Exception {
        try (FileInputStream keyRingFile = new FileInputStream("src/test/resources/secret-keyring.gpg")) {
            this.owner = new KeySetReader().read(keyRingFile).unlock("test".toCharArray());
        }

        try (FileInputStream anotherKeyRingFile = new FileInputStream("src/test/resources/another-secret-keyring.gpg")) {
            this.recipient = new KeySetReader().read(anotherKeyRingFile).unlock("test2".toCharArray());
        }

        // 1MB of data
        final Random random = new Random();
        this.original = new byte[1 << 20];
        random.nextBytes(original);
    }

    @Test
    public void isReadableByMessageReader() throws Exception {
        final MessageWriter writer = new MessageWriter(owner, Arrays.<KeySet>asList(recipient), new SecureRandom());

        final byte[] encrypted = writer.write(original);

        final MessageReader reader = new MessageReader(owner, recipient);
        final byte[] decrypted = reader.read(encrypted);

        assertThat(decrypted)
                .isEqualTo(original);
    }
}
