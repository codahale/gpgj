package com.codahale.gpgj;

import org.bouncycastle.bcpg.CompressionAlgorithmTags;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * A compression algorithm for OpenPGP messages.
 *
 * @see <a href="http://www.ietf.org/rfc/rfc4880.txt">Section 9.3, RFC 4880</a>
 */
public enum CompressionAlgorithm implements Flag {
    /**
     * Uncompressed
     *
     * @see <a href="http://www.cs.umd.edu/~jkatz/papers/pgp-attack.pdf">Implementation of Chosen-Ciphertext Attacks against PGP and GnuPG</a>
     * @deprecated Leaves messages vulnerable to adaptive chosen-plaintext attacks.
     */
    @Deprecated
    NONE("None", CompressionAlgorithmTags.UNCOMPRESSED),

    /**
     * ZLIB
     *
     * @see <a href="http://www.ietf.org/rfc/rfc1951.txt">RFC 1951</a>
     */
    ZLIB("ZLIB", CompressionAlgorithmTags.ZLIB),

    /**
     * ZIP
     *
     * @see <a href="http://www.ietf.org/rfc/rfc1950.txt">RFC 1950</a>
     */
    ZIP("ZIP", CompressionAlgorithmTags.ZIP),

    /**
     * BZip2
     *
     * @see <a href="http://www.bzip.org/">bzip.org</a>
     */
    BZIP2("BZIP2", CompressionAlgorithmTags.BZIP2);

    /**
     * The default compression algorithm to use.
     */
    public static final CompressionAlgorithm DEFAULT = ZLIB;

    /**
     * A set of compression algorithms which are acceptable for use in new systems.
     */
    public static final List<CompressionAlgorithm> ACCEPTABLE_ALGORITHMS =
            Collections.unmodifiableList(Arrays.asList(ZLIB, BZIP2, ZIP));

    private final String name;
    private final int value;

    private CompressionAlgorithm(String name, int value) {
        this.name = name;
        this.value = value;
    }

    /**
     * Returns the equivalent value of {@link CompressionAlgorithmTags}.
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
