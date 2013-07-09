package com.codahale.gpgj;

import org.bouncycastle.crypto.params.ECDomainParameters;

/**
 * Generates ECDSA master keys.
 *
 * @see <a href="http://en.wikipedia.org/wiki/ECDSA">ECDSA</a>
 * @see <a href="http://www.ietf.org/rfc/rfc6637.txt">RFC 6637</a>
 * @deprecated Not supported in GnuPG or BouncyCastle yet.
 */
@Deprecated
@SuppressWarnings("deprecation")
public class EcdsaKeyGenerator extends AbstractEcKeyGenerator implements MasterKeyGenerator {
    /**
     * Returns an {@link EcdsaKeyGenerator} which generates keys from the NIST P-256 curve.
     */
    public static EcdsaKeyGenerator ecdsaP256() {
        return new EcdsaKeyGenerator(P256);
    }

    /**
     * Returns an {@link EcdsaKeyGenerator} which generates keys from the NIST P-384 curve.
     */
    public static EcdsaKeyGenerator ecdsaP384() {
        return new EcdsaKeyGenerator(P384);
    }

    /**
     * Returns an {@link EcdsaKeyGenerator} which generates keys from the NIST P-521 curve.
     */
    public static EcdsaKeyGenerator ecdsaP521() {
        return new EcdsaKeyGenerator(P521);
    }

    private EcdsaKeyGenerator(ECDomainParameters parameters) {
        super(parameters);
    }

    @Override
    public AsymmetricAlgorithm getAlgorithm() {
        return AsymmetricAlgorithm.ECDSA;
    }
}
