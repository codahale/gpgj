package com.codahale.gpgj;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Date;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

/**
 * A multithreaded generator for {@link KeySet}s.
 * <p/>
 * Generates master keys using {@link AsymmetricAlgorithm#ENCRYPTION_DEFAULT},
 * and subkeys using {@link AsymmetricAlgorithm#SIGNING_DEFAULT}.
 */
public class KeySetGenerator {
    private static class GeneratorTask implements Callable<AsymmetricCipherKeyPair> {
        private final AsymmetricAlgorithm algorithm;
        private final SecureRandom random;
        private final KeyStrength strength;

        public GeneratorTask(AsymmetricAlgorithm algorithm, SecureRandom random, KeyStrength strength) {
            this.algorithm = algorithm;
            this.random = random;
            this.strength = strength;
        }

        @Override
        public AsymmetricCipherKeyPair call() throws Exception {
            final AsymmetricCipherKeyPairGenerator generator = algorithm.getGenerator();
            generator.init(algorithm.getParameters(random, strength));
            return generator.generateKeyPair();
        }
    }

    private final SecureRandom random;
    private final ExecutorService executor;
    private final AsymmetricAlgorithm signingAlgorithm;
    private final AsymmetricAlgorithm encryptingAlgorithm;
    private final KeyStrength strength;
    private final SymmetricAlgorithm symmetricAlgorithm;

    /**
     * Creates a new {@link KeySetGenerator}.
     *
     * @param random   a secure random number generator
     * @param executor a set of worker threads
     */
    public KeySetGenerator(SecureRandom random, ExecutorService executor) {
        this(random, executor, AsymmetricAlgorithm.SIGNING_DEFAULT,
             AsymmetricAlgorithm.ENCRYPTION_DEFAULT, KeyStrength.MEDIUM, SymmetricAlgorithm.DEFAULT);
    }

    /**
     * Creates a new {@link KeySetGenerator}.
     *
     * @param random              a secure random number generator
     * @param executor            a set of worker threads
     * @param signingAlgorithm    the algorithm to use for signatures
     * @param encryptingAlgorithm the algorithm to use for encryption
     * @param strength            the strength of keys to generate
     * @param symmetricAlgorithm  the symmetric algorithm to use
     */
    public KeySetGenerator(SecureRandom random,
                           ExecutorService executor,
                           AsymmetricAlgorithm signingAlgorithm,
                           AsymmetricAlgorithm encryptingAlgorithm,
                           KeyStrength strength,
                           SymmetricAlgorithm symmetricAlgorithm) {
        this.random = random;
        this.executor = executor;
        this.signingAlgorithm = signingAlgorithm;
        this.encryptingAlgorithm = encryptingAlgorithm;
        this.strength = strength;
        this.symmetricAlgorithm = symmetricAlgorithm;
    }

    /**
     * Generates a new {@link KeySet}.
     *
     * @param userId     the user ID, in {@code First Last <email@example.com>} format
     * @param passphrase the user's passphrase
     * @return a key set for the user
     * @throws CryptographicException if there was an error generating the key set
     */
    public KeySet generate(String userId, char[] passphrase) throws CryptographicException {
        try {
            final Date timestamp = new Date();
            final Future<AsymmetricCipherKeyPair> masterKeyPair = generateKeyPair(signingAlgorithm);
            final Future<AsymmetricCipherKeyPair> subKeyPair = generateKeyPair(encryptingAlgorithm);

            final BcPGPKeyPair masterPGPKeyPair = new BcPGPKeyPair(signingAlgorithm.value(),
                                                                   masterKeyPair.get(),
                                                                   timestamp);
            final PGPDigestCalculator calculator =
                    new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);

            final PGPContentSignerBuilder signer =
                    new JcaPGPContentSignerBuilder(masterPGPKeyPair.getPublicKey().getAlgorithm(),
                                                   HashAlgorithmTags.SHA1)
                            .setSecureRandom(random);

            final PBESecretKeyEncryptor encryptor =
                    new JcePBESecretKeyEncryptorBuilder(symmetricAlgorithm.value())
                            .setSecureRandom(random)
                            .build(passphrase);

            final PGPKeyRingGenerator generator =
                    new PGPKeyRingGenerator(SignatureType.POSITIVE_CERTIFICATION.value(),
                                            masterPGPKeyPair,
                                            userId,
                                            calculator,
                                            generateMasterKeySettings(),
                                            null, // only use hashed packets
                                            signer,
                                            encryptor);

            final BcPGPKeyPair subPGPKeyPair = new BcPGPKeyPair(encryptingAlgorithm.value(),
                                                                subKeyPair.get(),
                                                                timestamp);

            generator.addSubKey(subPGPKeyPair, generateSubKeySettings(), null); // likewise, use hashed packets

            return new KeySet(generator.generateSecretKeyRing());
        } catch (PGPException | InterruptedException | ExecutionException e) {
            throw new CryptographicException(e);
        }
    }

    private PGPSignatureSubpacketVector generateSubKeySettings() {
        final PGPSignatureSubpacketGenerator settings = new PGPSignatureSubpacketGenerator();
        settings.setKeyFlags(false, Flags.toBitmask(KeyFlag.SUB_KEY_DEFAULTS));
        return settings.generate();
    }

    private PGPSignatureSubpacketVector generateMasterKeySettings() {
        final PGPSignatureSubpacketGenerator settings = new PGPSignatureSubpacketGenerator();
        settings.setKeyFlags(false, Flags.toBitmask(KeyFlag.MASTER_KEY_DEFAULTS));
        settings.setPreferredSymmetricAlgorithms(false, Flags.toIntArray(SymmetricAlgorithm.ACCEPTABLE_ALGORITHMS));
        settings.setPreferredHashAlgorithms(false, Flags.toIntArray(HashAlgorithm.ACCEPTABLE_ALGORITHMS));
        settings.setPreferredCompressionAlgorithms(false, Flags.toIntArray(Arrays.asList(CompressionAlgorithm.BZIP2,
                                                                                         CompressionAlgorithm.ZLIB,
                                                                                         CompressionAlgorithm.ZIP)));
        return settings.generate();
    }

    private Future<AsymmetricCipherKeyPair> generateKeyPair(final AsymmetricAlgorithm algorithm) {
        return executor.submit(new GeneratorTask(algorithm, random, strength));
    }
}
