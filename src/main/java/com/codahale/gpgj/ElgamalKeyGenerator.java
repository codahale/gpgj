package com.codahale.gpgj;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ElGamalKeyPairGenerator;
import org.bouncycastle.crypto.params.ElGamalKeyGenerationParameters;
import org.bouncycastle.crypto.params.ElGamalParameters;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Generates Elgamal subkeys.
 *
 * @see <a href="http://en.wikipedia.org/wiki/ElGamal_encryption">Wikipedia</a>
 */
public class ElgamalKeyGenerator implements SubKeyGenerator {
    /*
     * Generated with `openssl dhparam -text 1024`.
     */
    private static final ElGamalParameters ELGAMAL_1024 = new ElGamalParameters(
            new BigInteger("00802cbe1efcd2f061546ff3704b26e1da88c325219c1fb544692d8b7692807055a8a" +
                                   "5fc135b46a3ad020236951a719c71d5193b25cc432782108a13b6d94df634" +
                                   "99dfb51b85b5ad89ce8fcf8364886c4a1b900a5d541b22c6b7358f0f7267e" +
                                   "c99b2f5542e274a23cef9888b1e21103e247387657318e42dbf9b52212913" +
                                   "4e14db", 16),
            new BigInteger("2")
    );

    /*
     * Generated with `openssl dhparam -text 2048`.
     */
    private static final ElGamalParameters ELGAMAL_2048 = new ElGamalParameters(
            new BigInteger("00bdcf78c8b26c804a8a223090cb14722e080a1c2acef2e4abb2a74a9755457079888" +
                                   "594efa7648c3f66e2eea7f8e3edea4d60890bb219f73a04bdd8fcba673acf" +
                                   "055e25b608bf7b7926c2645e3b36054f35a61a494ca1dc63894957e1afca7" +
                                   "a5e005ec7b27df35b44d19707301e0eeaeb07580db05d95f14da736cf494e" +
                                   "94c350dbb9e6185a6a4833fc19aa4a4ad2aad886360a93dc2909b8faa43d8" +
                                   "937e582567cfbad6074b2c5e066b2e8c7b0ecfb3ccc9c6eb40a13b1184ef9" +
                                   "dc55329bc13055fb027439154ee9317d27f439904f36bef683a4b405f010f" +
                                   "02e62544d18fb13dee6997a21551c0b616c584fe2daab6789861e122488dd" +
                                   "4b63384e7453ca35db", 16),
            new BigInteger("2")
    );

    /*
     * Generated with `openssl dhparam -text 4096`.
     */
    private static final ElGamalParameters ELGAMAL_4096 = new ElGamalParameters(
            new BigInteger("00bee98d72255c76e4174a7158a8c9c213c345182cbd17c1c09e94356053ec61e1df7" +
                                   "e025346599e28c2dd327e77ed8491d508bcf86fdf86b8661f1d637f7863ec" +
                                   "51ade9a1cbb26914f214ad54b0df16c3fe5f0cc105cf501338ec3a90c3fdb" +
                                   "758ef79a9b4b1d561d65899f07d49e79c43cb2d789792005c588240b49af9" +
                                   "8a24a206987612146e91e18f8f43b9d0addabe06ae068893ff65b3c0cf187" +
                                   "0b743eac16f02d720a3801ffa36bc2fb4269892ab9161761b776af6015a82" +
                                   "82c793e9271b74205cc038f5d02b661a4297896f729a21fd3060dc48c1c3d" +
                                   "52e5d18a2f4734f16cc375622790e76c9a0704fd4be9e0899d51c1657d4c9" +
                                   "0b3c8ae0adf79104bbf67c3bf1f47b63343ae5f0adef190eff5469d80761e" +
                                   "5036455933dbeb04666e2933c70d2624ad83f30eb051814cc10e81fd2b754" +
                                   "2d2b5480c2f78b1c362d7f608080cc896da4a0f54fdc52afa0f0a277a0d69" +
                                   "a5cdb11724fac32ce358650dd870c85f45c793dd92a98d2cb5ddb5fdb7fd3" +
                                   "c02cd69a9ba944370c7a7a290fd7710216828743c9c4e5966114c29d4afaf" +
                                   "33ac247374074ff71b2d1f70bbd6d28a137216e6025f79d4223d9722dedf5" +
                                   "37889e50b401b21204e7dc994580fa2e1bd3f06686585fb375c36cfe88503" +
                                   "85a5c31aa0869d4215d2ae0a898ca4ea3aac0c37c4c87b0a804dc9d35397c" +
                                   "ed19e2cb2945fc4d58de4730db81ceb39a41cd62d3", 16),
            new BigInteger("2")
    );

    /**
     * Returns an {@link ElgamalKeyGenerator} which generates 1024-bit master keys.
     */
    public static ElgamalKeyGenerator elgamal1024() {
        return new ElgamalKeyGenerator(ELGAMAL_1024);
    }

    /**
     * Returns an {@link ElgamalKeyGenerator} which generates 2048-bit master keys.
     */
    public static ElgamalKeyGenerator elgamal2048() {
        return new ElgamalKeyGenerator(ELGAMAL_2048);
    }

    /**
     * Returns an {@link ElgamalKeyGenerator} which generates 4096-bit master keys.
     */
    public static ElgamalKeyGenerator elgamal4096() {
        return new ElgamalKeyGenerator(ELGAMAL_4096);
    }

    private final ElGamalParameters parameters;

    private ElgamalKeyGenerator(ElGamalParameters parameters) {
        this.parameters = parameters;
    }

    @Override
    public AsymmetricCipherKeyPair generate(SecureRandom random) {
        final ElGamalKeyPairGenerator generator = new ElGamalKeyPairGenerator();
        generator.init(new ElGamalKeyGenerationParameters(random, parameters));
        return generator.generateKeyPair();
    }

    @Override
    public AsymmetricAlgorithm getAlgorithm() {
        return AsymmetricAlgorithm.ELGAMAL;
    }
}
