package com.codahale.gpgj;

import org.bouncycastle.crypto.params.ECDomainParameters;

/**
 * Generates ECDH subkeys.
 *
 * @see <a href="http://en.wikipedia.org/wiki/ECDH">ECDH</a>
 * @see <a href="http://www.ietf.org/rfc/rfc6637.txt">RFC 6637</a>
 * @deprecated Not supported in GnuPG or BouncyCastle yet.
 */
@Deprecated
@SuppressWarnings("deprecation")
public class EcdhKeyGenerator extends AbstractEcKeyGenerator implements SubKeyGenerator {
    /**
     * Returns an {@link EcdhKeyGenerator} which generates keys from the NIST P-256 curve.
     */
    public static EcdhKeyGenerator ecdhP256() {
        return new EcdhKeyGenerator(P256);
    }

    /**
     * Returns an {@link EcdhKeyGenerator} which generates keys from the NIST P-384 curve.
     */
    public static EcdhKeyGenerator ecdhP384() {
        return new EcdhKeyGenerator(P384);
    }

    /**
     * Returns an {@link EcdhKeyGenerator} which generates keys from the NIST P-521 curve.
     */
    public static EcdhKeyGenerator ecdhP521() {
        return new EcdhKeyGenerator(P521);
    }

    private EcdhKeyGenerator(ECDomainParameters parameters) {
        super(parameters);
    }

    @Override
    public AsymmetricAlgorithm getAlgorithm() {
        return AsymmetricAlgorithm.ECDH;
    }
}
