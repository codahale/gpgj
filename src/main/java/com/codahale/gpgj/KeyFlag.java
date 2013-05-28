package com.codahale.gpgj;

import java.util.EnumSet;
import java.util.Set;

/**
 * Flags for OpenPGP keys.
 *
 * @see <a href="http://www.ietf.org/rfc/rfc4880.txt">Section 5.2.3.21, RFC 4880</a>
 */
public enum KeyFlag implements Flag {
    // org.bouncycastle.openpgp.PGPKeyFlags is incomplete, and thus not
    // referenced here.

    /**
     * Indicates that the key can be used to certify other keys.
     */
    CERTIFICATION(0x01, "certifying other keys"),

    /**
     * Indicates that the key can be used to sign other keys.
     */
    SIGNING(0x02, "signing data"),

    /**
     * Indicates that the key can be used to encrypt communications and storage.
     * <p/>
     * <b>N.B.:</b> This includes both {@code 0x04}—"this key may be used to
     * encrypt communications"—and {@code 0x08}—"this key may be used to encrypt
     * storage."
     */
    ENCRYPTION(0x04 | 0x08, "encrypting data"),

    /**
     * Indicates that the key may be split via a secret-sharing mechanism.
     */
    SPLIT(0x10, "may be split via secret-sharing mechanism"),

    /**
     * Indicates that the key can be used for authentication.
     */
    AUTHENTICATION(0x20, "authentication"),

    /**
     * Indicates that the private components of the key may be in the possession
     * of more than one person.
     */
    SHARED(0x80, "may be in the possession of more than one person");

    /**
     * The default key flags for a master key.
     */
    public static final Set<KeyFlag> MASTER_KEY_DEFAULTS =
            EnumSet.of(SIGNING, AUTHENTICATION, SPLIT);

    /**
     * The default key flags for a sub key.
     */
    public static final Set<KeyFlag> SUB_KEY_DEFAULTS =
            EnumSet.of(ENCRYPTION, SPLIT);

    private final String name;
    private final int value;

    private KeyFlag(int value, String name) {
        this.name = name;
        this.value = value;
    }

    @Override
    public int value() {
        return value;
    }

    @Override
    public String toString() {
        return name;
    }
}
