package com.codahale.gpgj;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
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
import java.util.Date;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

/**
 * A multithreaded generator for {@link KeySet}s.
 */
public class KeySetGenerator {
    private final SecureRandom random;
    private final ExecutorService executor;
    private final MasterKeyGenerator masterKeyGenerator;
    private final SubKeyGenerator subKeyGenerator;
    private final SymmetricAlgorithm keyEncryptionAlgorithm;

    /**
     * Creates a new {@link KeySetGenerator}.
     *
     * @param random   a secure random number generator
     * @param executor a set of worker threads
     */
    public KeySetGenerator(SecureRandom random, ExecutorService executor) {
        this(random, executor, RsaKeyGenerator.rsa2048(), RsaKeyGenerator.rsa2048(),
             SymmetricAlgorithm.DEFAULT);
    }

    /**
     * Creates a new {@link KeySetGenerator}.
     *
     * @param random                 a secure random number generator
     * @param executor               a set of worker threads
     * @param masterKeyGenerator     the generator to use for master keys
     * @param subKeyGenerator        the generator to use for sub keys
     * @param keyEncryptionAlgorithm the symmetric algorithm to use to encrypt the private keys
     */
    public KeySetGenerator(SecureRandom random,
                           ExecutorService executor,
                           MasterKeyGenerator masterKeyGenerator,
                           SubKeyGenerator subKeyGenerator,
                           SymmetricAlgorithm keyEncryptionAlgorithm) {
        this.random = random;
        this.executor = executor;
        this.masterKeyGenerator = masterKeyGenerator;
        this.subKeyGenerator = subKeyGenerator;
        this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
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
            final Future<AsymmetricCipherKeyPair> masterKeyPair =
                    executor.submit(new Callable<AsymmetricCipherKeyPair>() {
                        @Override
                        public AsymmetricCipherKeyPair call() throws Exception {
                            return masterKeyGenerator.generate(random);
                        }
                    });
            final Future<AsymmetricCipherKeyPair> subKeyPair =
                    executor.submit(new Callable<AsymmetricCipherKeyPair>() {
                        @Override
                        public AsymmetricCipherKeyPair call() throws Exception {
                            return subKeyGenerator.generate(random);
                        }
                    });

            final BcPGPKeyPair masterPGPKeyPair =
                    new BcPGPKeyPair(masterKeyGenerator.getAlgorithm().value(),
                                     masterKeyPair.get(),
                                     timestamp);
            final PGPDigestCalculator calculator =
                    new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);

            final PGPContentSignerBuilder signer =
                    new JcaPGPContentSignerBuilder(masterPGPKeyPair.getPublicKey().getAlgorithm(),
                                                   HashAlgorithmTags.SHA1)
                            .setSecureRandom(random);

            final PBESecretKeyEncryptor encryptor =
                    new JcePBESecretKeyEncryptorBuilder(keyEncryptionAlgorithm.value())
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

            final BcPGPKeyPair subPGPKeyPair =
                    new BcPGPKeyPair(subKeyGenerator.getAlgorithm().value(),
                                     subKeyPair.get(),
                                     timestamp);

            generator
                    .addSubKey(subPGPKeyPair, generateSubKeySettings(), null); // likewise, use hashed packets

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
        settings.setPreferredCompressionAlgorithms(false, Flags.toIntArray(CompressionAlgorithm.ACCEPTABLE_ALGORITHMS));
        return settings.generate();
    }
}
