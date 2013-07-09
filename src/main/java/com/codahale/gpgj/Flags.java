package com.codahale.gpgj;

import java.util.*;

/**
 * Utility methods for dealing with {@link Flag}s.
 */
class Flags {
    private Flags() { /* singleton */ }

    static int[] toIntArray(List<? extends Flag> flags) {
        final int[] values = new int[flags.size()];
        int i = 0;
        for (Flag integerEquiv : flags) {
            values[i] = integerEquiv.value();
            i++;
        }
        return values;
    }

    static int toBitmask(Collection<? extends Flag> flags) {
        int value = 0;
        for (Flag integerEquiv : flags) {
            value |= integerEquiv.value();
        }
        return value;
    }

    static <T extends Flag> T fromInt(Class<T> enumType, int value) throws IllegalArgumentException {
        for (T constant : enumType.getEnumConstants()) {
            if (constant.value() == value) {
                return constant;
            }
        }
        throw new IllegalArgumentException("No enum constant of " + enumType + " exists with value " + value);
    }

    static <T extends Flag> List<T> fromIntArray(Class<T> enumType, int[] values) throws IllegalArgumentException {
        final List<T> enums = new ArrayList<>();
        for (int value : values) {
            enums.add(fromInt(enumType, value));
        }
        return Collections.unmodifiableList(enums);
    }

    static <T extends Flag> Set<T> fromBitmask(Class<T> enumType, int bitMask) throws IllegalArgumentException {
        final Set<T> enums = new HashSet<>();
        for (T constant : enumType.getEnumConstants()) {
            if ((bitMask & constant.value()) != 0) {
                enums.add(constant);
            }
        }
        return Collections.unmodifiableSet(enums);
    }
}
