package com.codahale.gpgj;

import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;

import java.security.SecureRandom;

/**
 * An abstract base class for ECC key generators.
 *
 * @deprecated Not supported in GnuPG or BouncyCastle yet.
 */
@Deprecated
abstract class AbstractEcKeyGenerator {
    protected static final ECDomainParameters P256;
    protected static final ECDomainParameters P384;
    protected static final ECDomainParameters P521;

    static {
        final X9ECParameters p256 = NISTNamedCurves.getByName("P-256");
        P256 = new ECDomainParameters(p256.getCurve(), p256.getG(), p256.getN(), p256.getH(), p256.getSeed());

        final X9ECParameters p384 = NISTNamedCurves.getByName("P-384");
        P384 = new ECDomainParameters(p384.getCurve(), p384.getG(), p384.getN(), p384.getH(), p384.getSeed());

        final X9ECParameters p521 = NISTNamedCurves.getByName("P-521");
        P521 = new ECDomainParameters(p521.getCurve(), p521.getG(), p521.getN(), p521.getH(), p521.getSeed());
    }

    private final ECDomainParameters parameters;

    protected AbstractEcKeyGenerator(ECDomainParameters parameters) {
        this.parameters = parameters;
    }

    public AsymmetricCipherKeyPair generate(SecureRandom random) {
        final ECKeyPairGenerator generator = new ECKeyPairGenerator();
        generator.init(new ECKeyGenerationParameters(parameters, random));
        return generator.generateKeyPair();
    }
}
