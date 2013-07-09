package com.codahale.gpgj;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;

/**
 * An asymmetric encryption or signing algorithm for OpenPGP messages.
 *
 * @see <a href="http://www.ietf.org/rfc/rfc4880.txt">Section 9.1, RFC 4880</a>
 */
public enum AsymmetricAlgorithm implements Flag {
    /**
     * Elgamal (Encrypt-Only)
     *
     * @see <a href="http://en.wikipedia.org/wiki/ElGamal_encryption">Wikipedia</a>
     */
    ELGAMAL("Elgamal", PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT),

    /**
     * DSA (Digital Signature Algorithm)
     *
     * @see <a href="http://en.wikipedia.org/wiki/Digital_Signature_Algorithm">Wikipedia</a>
     */
    DSA("DSA", PublicKeyAlgorithmTags.DSA),

    /**
     * RSA (Encrypt or Sign)
     *
     * @see <a href="http://en.wikipedia.org/wiki/RSA">Wikipedia</a>
     */
    RSA("RSA", PublicKeyAlgorithmTags.RSA_GENERAL),

    /**
     * RSA Encrypt-Only
     *
     * @see <a href="http://www.ietf.org/rfc/rfc4880.txt">Section 13.5, RFC 4880</a>
     * @deprecated Sign-only keys must be expressed with subpackets in v4 keys.
     */
    @Deprecated
    RSA_E("RSA(e)", PublicKeyAlgorithmTags.RSA_ENCRYPT),

    /**
     * RSA Sign-Only
     *
     * @see <a href="http://www.ietf.org/rfc/rfc4880.txt">Section 13.5, RFC 4880</a>
     * @deprecated Sign-only keys must be expressed with subpackets in v4 keys.
     */
    @Deprecated
    RSA_S("RSA(s)", PublicKeyAlgorithmTags.RSA_SIGN),

    /**
     * Elliptic Curve
     *
     * @see <a href="http://www.ietf.org/rfc/rfc4880.txt">Section 13.8, RFC 4880</a>
     * @deprecated Underspecified in RFC 4880, not supported in GnuPG.
     */
    @Deprecated
    EC("EC", PublicKeyAlgorithmTags.EC),

    /**
     * Elliptic Curve Digital Signature Algorithm.
     *
     * @see <a href="http://www.ietf.org/rfc/rfc4880.txt">Section 13.8, RFC 4880</a>
     * @deprecated Underspecified in RFC 4880, not supported in GnuPG.
     */
    @Deprecated
    ECDSA("ECDSA", PublicKeyAlgorithmTags.ECDSA),

    /**
     * Elgamal (Encrypt or Sign)
     *
     * @see <a href="http://www.ietf.org/rfc/rfc4880.txt">Section 13.8, RFC 4880</a>
     * @see <a href="http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.45.3347">Generating ElGamal signatures without knowing the secret key; Daniel Bleichenbacher</a>
     * @deprecated Prohibited by RFC 4880 due to vulnerabilities.
     */
    @Deprecated
    ELGAMAL_G("Elgamal(g)", PublicKeyAlgorithmTags.ELGAMAL_GENERAL),

    /**
     * Diffie-Hellman (X9.42, as defined for IETF-S/MIME)
     *
     * @see <a href="http://www.ietf.org/rfc/rfc4880.txt">Section 13.8, RFC 4880</a>
     * @deprecated Underspecified in RFC 4880.
     */
    @Deprecated
    DH("DH", PublicKeyAlgorithmTags.DIFFIE_HELLMAN);

    private final String name;
    private final int value;

    private AsymmetricAlgorithm(String name, int value) {
        this.name = name;
        this.value = value;
    }

    /**
     * Returns the algorithm's standard name.
     */
    public String getName() {
        return name;
    }

    /**
     * Returns the equivalent value of {@link PublicKeyAlgorithmTags}.
     */
    @Override
    public int value() {
        return value;
    }

    @Override
    public String toString() {
        return name;
    }
}
