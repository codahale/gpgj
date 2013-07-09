package com.codahale.gpgj;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.DSAKeyPairGenerator;
import org.bouncycastle.crypto.params.DSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameters;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Generates DSA master keys.
 *
 * @see <a href="http://en.wikipedia.org/wiki/Digital_Signature_Algorithm">Wikipedia</a>
 */
public class DsaKeyGenerator implements MasterKeyGenerator {
    /*
     * Generated with `openssl dsaparam -text 1024`.
     */
    private static final DSAParameters DSA_1024 = new DSAParameters(
            new BigInteger("00e62ade78901baf65003aa0fbf18b601da0b53a6d25357e94a13fe6e5820ca343182" +
                                   "b1539b038953bcaff1269f490bd1af40da5d0086be33361a11cae78d3465a" +
                                   "c270a8c9505b31d45017d8ef9feb830c18e6f4090ec918c1e1de32ac85e39" +
                                   "ac574d073bba30a0974987a8ce1ffc8aebe0095f5a4de6a52e8ecc3c99bf9" +
                                   "bda02f", 16),
            new BigInteger("00e26657957f452e9fd0d67992afc207f8f04aadfb", 16),
            new BigInteger("33a6a71f1249e74a1ac3b1d682cf0b1b8208dfddffaabf9e1d8fac8f27bc8fa487d15" +
                                   "cf3151db9c62d8c07464346b676a00abecdee7cefe8224f5260855ec50e48" +
                                   "0cb369ccdb1243b32e5bd378e66b1f173d6909b7df6bbd3999815da954aa7" +
                                   "0e1fbab7dc57281865ff3270d9356f61ff47a0d672cac69e6e7478113d044" +
                                   "4928", 16));
    /*
     * Generated with `openssl dsaparam -text 2048`.
     */
    private static final DSAParameters DSA_2048 = new DSAParameters(
            new BigInteger("00a6ecd8eb3031a0ed05f95addb307536710ee9bd405fef661581005dc63ab9049ae8" +
                                   "6f90fc64ff57c16b0353482bcf4e597082ed22522149377fea0307f0d44ce" +
                                   "8b8c226b3fb4ab87c60a1156606ffc6e2b020d0da55adcc67f190d5a766e1" +
                                   "5c8cfb83d807f27de78f3fe75e2c8f67b984ea2b1ca5bcd5d241c14593b4b" +
                                   "3743dab70906461e41635d91bd4e712635ba3f4af5ebeb0a5bb1d617a8f56" +
                                   "36f3b3429834395fc6857a3e21e4f0f185d9f750a48dbac361be1c02d22c0" +
                                   "65f945a184013e4addc7cde61ce84e9cd8141d962e70ccda0a5e893afe1a5" +
                                   "42bfad9a127f2af4469fe66cc47ca8820e50c6fe08d15934ad306b66dd87e" +
                                   "e971e8ada30bd3890b", 16),
            new BigInteger("00efe3c0f9283d4f8e3c7327f7ae2cdf3409e497b4c01f31052f9a97df042c799d", 16),
            new BigInteger("0092811cf2cedd84f9adf6f9955df6213ed8d5b2f3485286213f4af174f4888005521" +
                                   "2336d0e8aee5460c850db7e2096341bf5560e26d41345142bff9278d7ef8d" +
                                   "9ee2187843df9f1ea22a2b8fd6e8245f5764bd7dca1091224cde04c37300a" +
                                   "da108faa5c09393bf9bdac9e4c5e67b7a7e92e279badd3ca0d861cbafb32e" +
                                   "00b532df6fd9547c87262a51b8e3c9b698eda5f0c3e1e54f01ce7fef088e7" +
                                   "f702a155f4f2cbf0df3d36500f0bb5442dd6fb56b2a7b0685fdd3d3aa8366" +
                                   "ef0f41f2e7407556b7e412d7719310758735d4ab1fccfa6cffec3748f6816" +
                                   "d785920da6493152a372d291eb844639c66e93f9342e5cedfdc9b4df0811a" +
                                   "b6f44841da1acd50a3", 16)
    );

    /*
     * Generated with `openssl dsaparam -text 3072`.
     */
    private static final DSAParameters DSA_3072 = new DSAParameters(
            new BigInteger("00bb2f37caf33498d51830218faad81039db9a345385e16dd79f005f1524c63062e9d" +
                                   "7326c374438a507b3b433cb527e311c5ac952fcde0182c71fac828c1e15a3" +
                                   "0d95eeeca4218b13b3f17d8400e8f6b61922ba066221af15e5fcdacc214be" +
                                   "fc9eb5cff6a66c45ecd0c025f1cf04d2c5146679ce9902f109ad823ff1a54" +
                                   "565f753cf39c62bf837c7b8bc1d5628a3b86c41d24edad363af0a07975c5c" +
                                   "cc0a82346899994c8c94fa022fcd1936674d5531837b7889f2491d1d11362" +
                                   "580f9c38ac8fe704f0ff7e0f8e8f929842d6815ffe91a8363d11ef0202847" +
                                   "565b210d2a07e38ab25a0bb4dc3fd9f4befdf3030f5c86cb822ca7f8dffc4" +
                                   "ffdbaa4e2727491361ba45e87c17e400554a8384b3331be128e003ec46706" +
                                   "0da7a356b99aa570e32c9e4000d786bf42fb8e324780e2dad2e740557b160" +
                                   "41297c63ee8cef5d96c0812fd7d2d0213237881c3f4c54290d4df7f86041a" +
                                   "e089c379663b32aab968958858f492435bcea0ddbcc278cb4368a14262f9c" +
                                   "7fdf8f05eb981f0dc79e6cd44022e5", 16),
            new BigInteger("00d886cee189708271e4d460a2efc0815dbe2230671799cff049b4a9d6eebebe85", 16),
            new BigInteger("00812b85a2738b5f13ef3826c36cdd04cdee408a34c42f88f103dc30aae7d33069150" +
                                   "6d904bde69b387c272466eaf704e42f05b6d5aeb3e1e871e64cf19d9d866a" +
                                   "1d03f7d9916c70abe77537cc50c1683324bd90f44abbbd053201fcd267425" +
                                   "b8bdacd5ca88f4952db5cd2d262b93fc80793d8512d0e6116d957ee2c3af4" +
                                   "84731b43e911e8c9a98b9d610d8b9a8297ef45a0a1f519478307d9133f026" +
                                   "15719708061d6acaf27c7d88a0dac66c277ce649ef22fea740e44fe6f5c71" +
                                   "91a9ea9c9265d0a95f0318c2bd81f234a8fc52e90e93e0e83d2d0f79dcad2" +
                                   "f55fce41519467a4ad74f5676ddf658163ddf4b4ae886a3762e5b28c2b30f" +
                                   "b8f78b902015d1cf08c8e134dc0dca5593345c9f66e7590f05aa755644795" +
                                   "6bf346519ca33db85ac7a5a3d8928e4d953ae4cc22e7ec6944d898d7fe314" +
                                   "b772aaff132e4b978ea972b6529aa0de58453c4d1debd24abed7e4bf14d65" +
                                   "c6790cfa75b1eda98a0805200a381cc45b30635ca2fa34ef34cd5ca30d154" +
                                   "3662293e0dcb67aa2f26992834150b", 16)
    );

    /**
     * Returns a {@link DsaKeyGenerator} which generates 1024-bit master keys.
     */
    public static DsaKeyGenerator dsa1024() {
        return new DsaKeyGenerator(DSA_1024);
    }

    /**
     * Returns a {@link DsaKeyGenerator} which generates 2048-bit master keys.
     */
    public static DsaKeyGenerator dsa2048() {
        return new DsaKeyGenerator(DSA_2048);
    }

    /**
     * Returns a {@link DsaKeyGenerator} which generates 3072-bit master keys.
     */
    public static DsaKeyGenerator dsa3072() {
        return new DsaKeyGenerator(DSA_3072);
    }

    private final DSAParameters parameters;

    private DsaKeyGenerator(DSAParameters parameters) {
        this.parameters = parameters;
    }

    @Override
    public AsymmetricCipherKeyPair generate(SecureRandom random) {
        final DSAKeyPairGenerator generator = new DSAKeyPairGenerator();
        generator.init(new DSAKeyGenerationParameters(random, parameters));
        return generator.generateKeyPair();
    }

    @Override
    public AsymmetricAlgorithm getAlgorithm() {
        return AsymmetricAlgorithm.DSA;
    }
}
