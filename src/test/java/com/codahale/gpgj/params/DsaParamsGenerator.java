package com.codahale.gpgj.params;

import org.bouncycastle.jcajce.provider.asymmetric.dsa.AlgorithmParameterGeneratorSpi;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.DSAParameterSpec;
import java.util.Arrays;

public class DsaParamsGenerator {
    private static class DsaGeneratorSpi extends AlgorithmParameterGeneratorSpi {
        @Override
        public void engineInit(int strength, SecureRandom random) {
            super.engineInit(strength, random);
        }

        @Override
        public AlgorithmParameters engineGenerateParameters() {
            return super.engineGenerateParameters();
        }
    }

    public static void main(String[] args) throws Exception {
        // re-use the JCE SPI for BC's DSA param generation
        Security.addProvider(new BouncyCastleProvider());
        final SecureRandom random = new SecureRandom();
        final DsaGeneratorSpi spi = new DsaGeneratorSpi();
        for (int size : Arrays.asList(1024, 2048, 3072)) {
            System.out.printf("Generating %d-bit parameters...%n", size);
            spi.engineInit(size, random);
            final AlgorithmParameters params = spi.engineGenerateParameters();
            final DSAParameterSpec dsaParams = params.getParameterSpec(DSAParameterSpec.class);
            System.out.printf("P = %n%s%n%n", format(dsaParams.getP()));
            System.out.printf("Q = %n%s%n%n", format(dsaParams.getQ()));
            System.out.printf("G = %n%s%n%n", format(dsaParams.getG()));
        }
    }

    private static String format(BigInteger n) {
        final String s = n.toString(16).toUpperCase();
        final StringBuilder result = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            result.append(s.charAt(i));
            if ((i + 1) % 8 == 0) {
                result.append(" ");
            }
            if ((i + 1) % 48 == 0) {
                result.append("\n");
            }
        }
        return result.toString();
    }
}
