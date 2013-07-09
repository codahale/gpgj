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
    protected static final ECDomainParameters P256 = convert(NISTNamedCurves.getByName("P-256"));
    protected static final ECDomainParameters P384 = convert(NISTNamedCurves.getByName("P-384"));
    protected static final ECDomainParameters P521 = convert(NISTNamedCurves.getByName("P-521"));

    private static ECDomainParameters convert(X9ECParameters params) {
        return new ECDomainParameters(params.getCurve(), params.getG(), params.getN(),
                                      params.getH(), params.getSeed());
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
