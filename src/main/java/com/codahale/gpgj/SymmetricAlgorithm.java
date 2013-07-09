package com.codahale.gpgj;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * A symmetric encryption algorithm for OpenPGP messages.
 *
 * @see <a href="http://www.ietf.org/rfc/rfc4880.txt">Section 9.2, RFC 4880</a>
 */
public enum SymmetricAlgorithm implements Flag {
    /**
     * Plaintext or unencrypted data
     *
     * @deprecated Do not store unencrypted data.
     */
    @Deprecated
    PLAINTEXT("Plaintext", SymmetricKeyAlgorithmTags.NULL),

    /**
     * IDEA
     *
     * @deprecated Encumbered by patents.
     */
    @Deprecated
    IDEA("IDEA", SymmetricKeyAlgorithmTags.IDEA),

    /**
     * TripleDES (DES-EDE, 168 bit key derived from 192)
     *
     * @deprecated Replaced by AES.
     */
    @Deprecated
    TRIPLE_DES("3DES", SymmetricKeyAlgorithmTags.TRIPLE_DES),

    /**
     * CAST-128 (also known as CAST5)
     *
     * @see <a href="http://www.ietf.org/rfc/rfc2144.txt">RFC 2144</a>
     * @deprecated
     */
    @Deprecated
    CAST_128("CAST-128", SymmetricKeyAlgorithmTags.CAST5),

    /**
     * Blowfish (128 bit key, 16 rounds)
     *
     * @deprecated
     */
    @Deprecated
    BLOWFISH("Blowfish", SymmetricKeyAlgorithmTags.BLOWFISH),

    /**
     * SAFER-SK (128 bit key, 13 rounds)
     *
     * @deprecated Not specified by RFC 4880.
     */
    @Deprecated
    SAFER_SK("SAFER-SK", SymmetricKeyAlgorithmTags.SAFER),

    /**
     * DES (56 bit key)
     *
     * @deprecated Not specified by RFC 4880.
     */
    @Deprecated
    DES("DES", SymmetricKeyAlgorithmTags.DES),

    /**
     * AES with 128-bit key
     */
    AES_128("AES-128", SymmetricKeyAlgorithmTags.AES_128),

    /**
     * AES with 192-bit key
     */
    AES_192("AES-192", SymmetricKeyAlgorithmTags.AES_192),

    /**
     * AES with 256-bit key
     */
    AES_256("AES-256", SymmetricKeyAlgorithmTags.AES_256),

    /**
     * Twofish with 256-bit key
     *
     * @deprecated
     */
    @Deprecated
    TWOFISH("Twofish", SymmetricKeyAlgorithmTags.TWOFISH);

    /**
     * The default symmetric algorithm to use.
     */
    public static final SymmetricAlgorithm DEFAULT = AES_256;

    /**
     * A set of symmetric algorithms which are acceptable for use in new systems.
     */
    public static final List<SymmetricAlgorithm> ACCEPTABLE_ALGORITHMS =
            Collections.unmodifiableList(Arrays.asList(AES_256, AES_192, AES_128));

    private final String name;
    private final int value;

    private SymmetricAlgorithm(String name, int value) {
        this.name = name;
        this.value = value;
    }

    /**
     * Returns the equivalent value of {@link SymmetricKeyAlgorithmTags}.
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

