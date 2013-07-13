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
    /**
     * Generated 1024/160 DSA parameters.
     */
    private static final DSAParameters DSA_1024 = new DSAParameters(
            new BigInteger(("D808D06F 0308F8ED C9DE9A34 896ECB37 2349B6D4 09BB1EEB" +
                            "603834DC 00ECFD72 E2D81800 6A8C02C4 194AA475 F3268E7F" +
                            "EE2FA905 FAB996A7 98F71458 57528EBC 7F0D1558 BA10F3DA" +
                            "8231DA65 B08AEA6E B74F9A52 62305F94 DAFE1B9F 423D53A1" +
                            "1308B9FE 24679AE9 4612C4A3 33BF643D D2056071 9B5319CF" +
                            "67D616CB AA94BB05")
                                   .replaceAll("[\\s]+", ""), 16),
            new BigInteger(("DB1590AE 2BE9C2DA B9B059BC 11781CFB 0E493F29")
                                   .replaceAll("[\\s]+", ""), 16),
            new BigInteger(("5ED4A48F 1D1508BD D73B820D C68583E3 CD57A1E8 A5D68872" +
                            "708C59D4 9255DCED 5B3D3D0F 51C3584D 374784B7 C4C1C123" +
                            "979AEBB1 E2A42F3C B99759CD 68C87511 30E46707 91C643DF" +
                            "797086D3 0D144C27 595C5EAB 9AA4ED92 85137F10 82D8D28A" +
                            "4C5B47D3 8CFDBF7A 4014EF13 F17BF32D FF134603 A914DE1B" +
                            "3656C108 20EB83F9")
                                   .replaceAll("[\\s]+", ""), 16));
    /**
     * Generated 2048/256 DSA2 parameters.
     */
    private static final DSAParameters DSA_2048 = new DSAParameters(
            new BigInteger(("9230ED82 5E8049A4 27DE7DC5 978B3C1D 8D67BC87 3AAABBBE" +
                            "0C1BE83F 6083BCC5 CE23471C 8FF8575E 1D250198 FA247694" +
                            "16C2B113 37734C50 9461E60A D704DE3C 57E6AE95 729C8368" +
                            "A01531AE 1D8A6F73 4A827A89 AA027D58 3AA9141D 2E8E7FB2" +
                            "036419C8 43573B90 00F321FB 2E7144E1 CA770A58 04802520" +
                            "B6E7B886 735BFD16 58DD0C50 5886B88A EBB626BB 35D61C02" +
                            "EC1DEE0C 64BF45C7 BC383B09 08BF16E9 C263F68C CF4BDD08" +
                            "C3ED6033 36D79554 15FED93B A82A8B4B 3C186A99 1838DC64" +
                            "3277A22F CA03F851 2998C8F4 E6E970EA 211F9AF1 67F7F761" +
                            "E453D767 46AC0D57 830806D7 721FC596 8031CBD8 B5BAAA3B" +
                            "0E568AAD A35F35AB BFD0DF54 8134E993")
                                   .replaceAll("[\\s]+", ""), 16),
            new BigInteger(("BBDF6554 B8FDD2DD 648D49DE DD16B29A 87114B33 D82ED64D" +
                            "82F0AD4A 4DAF33ED").replaceAll("[\\s]+", ""), 16),
            new BigInteger(("321F9448 60657BC8 ADBE119E 39557AF9 EDE8B09E 97B5C270" +
                            "08E8048B E5165643 6355572B D44E383E 57EE993F 556FBF7A" +
                            "B60AC042 97B116E6 38B0F930 A0BC1AEC E6142C77 470CE357" +
                            "F3C8582D E9FC1ECE D21B3B97 73E020AE 1DEF5C40 F7972C31" +
                            "48307D0D 982EB158 0F5FEFF1 DE427B16 E9EA132F 977CE9F7" +
                            "A85A2DAB D586A639 119C5D2A CBFB1591 9E3828AD 283547BA" +
                            "FF774BEF 02671CF0 9FFF3AC6 28ABAFF7 495426AB 6A7F84E8" +
                            "CC98F154 44ECDDF4 BDC1DD52 EAA8E163 24128919 1CE5F991" +
                            "BBB68E25 C0EDDFAC 93365C1F AB941AC1 215D25B0 CE939C7D" +
                            "3BD71BAA CF274A45 2A733DD9 4D1DA8BA A7E1FE1B 5596D117" +
                            "87D13227 CA5D7E8E 2A927271 0887C509")
                                   .replaceAll("[\\s]+", ""), 16)
    );

    /**
     * Generated 3072/256 DSA2 parameters.
     */
    private static final DSAParameters DSA_3072 = new DSAParameters(
            new BigInteger(("94B5F252 6145F1E6 44966718 D9440771 8B04064C 900C9F26" +
                            "6EE923F1 5C56A95B A9CDE0E9 A47A8092 5450E929 4EABA441" +
                            "6150E513 65730E35 50F7BBCD 2EAD09BB 33AD0295 1BA06E9E" +
                            "38384959 C8120D9D 1853C54F 26B12F5A B449AEF8 A4C3ACB3" +
                            "1D05EA3F 4429511B 224AD54A C7CBE62F 4F1E9BB8 AE93CA34" +
                            "7E3FDC92 D3F7B2D4 5B84C22F 58972970 B186C3BA 6694356F" +
                            "DC4707E6 1F3DBE7E 0F4DD46F 11488460 E6BC2033 9A88B23B" +
                            "FD18F538 5A23CE6F D4D92ADC B74830B1 17660D14 566DB32E" +
                            "C9E8D930 C428EB7C 915C34F7 78A98747 117CCF1C 14D91BBA" +
                            "1BE03296 A18D488D CF6161B8 06BDAE43 04B8147A 861A0F5A" +
                            "7017BBC3 297578BF DAB54917 25A233D3 2C8CB3C7 6B85D6A9" +
                            "7F276B2C 1F1488DD 13FA9050 357DD722 6CDF352D AF36E2B0" +
                            "ACE731F1 AE3D629C 82710374 F03DF3C6 43A4122C 2C89B5FA" +
                            "76F32F1A B7A85515 C412B5A2 F4571512 293F4E5B 0AD710DC" +
                            "CB5488BA 9BA22301 C6584C04 6E16E0CA 2B33CFD2 B123BA76" +
                            "2026695E 493CF6BB 6B7997FB 6893ACCD 30652E66 53C5D0A9")
                                   .replaceAll("[\\s]+", ""), 16),
            new BigInteger(("8CE9107D 263AF57B 481CFA76 0E6D2AEF 776F5BC5 A719D7B5" +
                            "751BB319 4905A36F")
                                   .replaceAll("[\\s]+", ""), 16),
            new BigInteger(("2CF61C09 A9E3E762 C314D0D9 384E8F00 3932306B BCC2D286" +
                            "5A179A10 80F566C3 B9F53E8A CBB092FC CBDAECCC 0DAFAF5B" +
                            "DF29A825 6FD12190 922FF96F 7B2CC830 BAA6A2C7 08CE6DD0" +
                            "CDD8BE58 55E96B9A 250BD91A 6896B037 36CF3F76 BA2278EF" +
                            "B85E93AA 3F9A6551 5D6EDA94 24C0FD24 3B1F9758 34C92CDC" +
                            "09ECC1BF 816E5045 874BE7F0 4813AD4A 386A1E71 2A1D7DD0" +
                            "8826B2E7 4F3CEFB4 83CD4A35 A4E074A8 E5188322 7E432B39" +
                            "7DFFDBF1 5A56FCA3 8D7A444F 7A5AD652 8EFDD9A8 B8547538" +
                            "CACAC3FB 91D0B1EF 4A93561A 97BBB379 750562F5 56703169" +
                            "422F116D E3AA3C1B EEE803FD 5DBFAB86 BE5EED7E 0EC049F8" +
                            "2EEAD0BA 3A074B04 3B57F9B7 E547AC84 C48CF250 895516EB" +
                            "DF91C478 04BAB943 F3CEE677 F5CEE3C5 180C5E52 571D9899" +
                            "3475EE79 7655055F 1BA376AD 18ADDDE4 97636BA0 8C6483D4" +
                            "5C244333 81305A62 4DBFA4E6 8125FB3D 6C916F33 062B0194" +
                            "64E32B8A 70F5C9E8 3C460270 5D4BE26C 83C28DFF 5D18456E" +
                            "3F5D2FF6 99AA3F26 BD236515 3E67CFC6 E2AC1578 3F2A5B65")
                                   .replaceAll("[\\s]+", ""), 16)
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
