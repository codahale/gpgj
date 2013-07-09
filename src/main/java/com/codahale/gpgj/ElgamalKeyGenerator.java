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

    /*
     * Generated with `openssl dhparam -text 8192`.
     */
    private static final ElGamalParameters ELGAMAL_8192 = new ElGamalParameters(
            new BigInteger("00c3ba5e4bf830445cfd46a0c8350accb357be3dceb840ccf52612288367bb9cff4d1" +
                                   "989b290c31c6878513acb0bce42d5e5a71633a04fa75904df2b3f6c494724" +
                                   "2804b34d51913daac5956aedfd7b30aef8932588f13ebe688f06a1496da22" +
                                   "5f623463c55387a7319f1237e9d6a3263f309fd01937cd8592ca98866cd53" +
                                   "e4543b3966e613638c9535bc6c60cf3f955015e3cd2e6383c616eb9cc7447" +
                                   "c137732fe32a5dacc17e756ea92de9aff4bdca78ea957837d5f04cd5783c6" +
                                   "f9c3c953e1eade1f3468a1a605963a9599304f3b9f3f7134c1a6edee5bc72" +
                                   "8c20bac54585dc229d549ab3235e7c69b7ad09ebd662fec252ffb45494f49" +
                                   "0421ceff89a5bc7a2e04ec4c418c8c77486e704c74c17c2d6b1e78198102b" +
                                   "d095129a4ba017038dd06900505defd06408725cc5a81b19132b726eedaf5" +
                                   "e90e6e90128c4995cb3ac56b14e02718609f66ad78af7284003e6f3ed9704" +
                                   "a6a5ff082c3d5b02a821cf09dcf8dee152b906346013542e9fd727f9b9a0b" +
                                   "94719f863758a40e488541e200e15e09eefddfe7f965553e1e0db53bbb269" +
                                   "1fd38736cee8fd0f40b5c0e0ad44fb3729080a0ccfcc1dedeb618ecdecf2b" +
                                   "202bfedf80448ac51d3cd75af0368ff238885e0a148c8f1ff575765ab39fc" +
                                   "55848e79cb0383f6d0eed338ec81a1921e4467b850d3955820bd5419a1ecc" +
                                   "4639aeb7a21b485a46997f930075ff897f5b8ba3c8396234fdb12b7b4dac2" +
                                   "f80b66ba39e4849d0d425f051d45fbeaf66cf15de4fdaf240ee0eed6c4cab" +
                                   "cb83c0aee2355041cdd823594473e50077c328cd0951eb623ece21b7a773f" +
                                   "10e461aa016812afbcda55f1da2b45524403b049069819537575fe9e9a284" +
                                   "602b7c1f38bd35440546e6e29d4715fb977638c71f372eea5d70758821a50" +
                                   "861f6c932e23c5004ba3d63f2c0f01a02cd5ac120aa36311f80302e5a3c98" +
                                   "a20de7a07a94b0e034c392d519ed06cf481e240f25889470757f6d5668941" +
                                   "a6dc128aa9ee92ff266afa76df4182a1fb1cc1c19b9994e71da2f2e8ade32" +
                                   "9abbd576221890b71c590e3cec9f03cf0de89e092b751916ba8f140c5a1f4" +
                                   "94c664713559d5fa400e71d7cab86bafcf5bb2660d4ee030f9ed10c2ad0b8" +
                                   "9f502a291cc567267b6b71f05ec0debc76882456a1d74dcf9290145e1b430" +
                                   "fbc0519cc2097f573b605d26061d7bcd399fac1163157bbe6aea7e444a2eb" +
                                   "fa2f1fbbdff4e296798c8812b77f5dce80dfe1fbc43eeaf96c0f3335defbe" +
                                   "4f6ccae061d31c0b1f5732b17f3afda6c12b593167d6092dd083e42bbb9e6" +
                                   "e1f81ab0eb7f1cc4395d2ad5e06cd9645ba95bb6cff42acdefbb89dc6510e" +
                                   "dcb4debf508aea3e0f1486f680abfc52d90ca5183ca0cf7794229af8f3ceb" +
                                   "31e9a4c6c3fe149163f455d5fb380cedf596303d327a5ba42d1d5ad6268dc" +
                                   "5d8554226ec46319f1771b6ef8de3", 16),
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

    /**
     * Returns an {@link ElgamalKeyGenerator} which generates 8192-bit master keys.
     */
    public static ElgamalKeyGenerator elgamal8192() {
        return new ElgamalKeyGenerator(ELGAMAL_8192);
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
