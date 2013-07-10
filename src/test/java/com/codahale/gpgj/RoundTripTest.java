package com.codahale.gpgj;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.fest.assertions.api.Assertions.assertThat;

@RunWith(Theories.class)
public class RoundTripTest {
    @DataPoints
    public static MasterKeyGenerator[] MASTER_GENERATORS = {
            DsaKeyGenerator.dsa1024(),
            DsaKeyGenerator.dsa2048(),
            DsaKeyGenerator.dsa3072(),
            RsaKeyGenerator.rsa1024(),
            RsaKeyGenerator.rsa2048(),
    };

    @DataPoints
    public static SubKeyGenerator[] SUB_GENERATORS = {
            ElgamalKeyGenerator.elgamal1536(),
            ElgamalKeyGenerator.elgamal2048(),
            ElgamalKeyGenerator.elgamal4096(),
            RsaKeyGenerator.rsa1024(),
            RsaKeyGenerator.rsa2048(),
    };

    private static ExecutorService THREAD_POOL;

    @BeforeClass
    public static void setUp() throws Exception {
        THREAD_POOL = Executors.newFixedThreadPool(8);
    }

    @AfterClass
    public static void tearDown() throws Exception {
        THREAD_POOL.shutdown();
    }

    @Theory
    public void roundTripsAMessage(MasterKeyGenerator masterGenerator,
                                   SubKeyGenerator subKeyGenerator) throws Exception {
        final KeySetGenerator generator = new KeySetGenerator(new SecureRandom(),
                                                              THREAD_POOL,
                                                              masterGenerator,
                                                              subKeyGenerator,
                                                              SymmetricAlgorithm.AES_128);
        final KeySet keySet = generator.generate("one", "yay".toCharArray());
        final UnlockedKeySet unlockedKeySet = keySet.unlock("yay".toCharArray());

        final MessageWriter writer = new MessageWriter(unlockedKeySet,
                                                       Arrays.asList(keySet),
                                                       new SecureRandom());
        final byte[] encrypted = writer.write("oh hello".getBytes(StandardCharsets.US_ASCII));

        final MessageReader reader = new MessageReader(keySet, unlockedKeySet);
        final byte[] decrypted = reader.read(encrypted);

        assertThat(new String(decrypted, StandardCharsets.US_ASCII))
                .isEqualTo("oh hello");
    }
}
