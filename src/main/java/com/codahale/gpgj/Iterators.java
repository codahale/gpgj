package com.codahale.gpgj;

import java.util.*;

/**
 * Utility methods for dealing with untyped {@link Iterator} instances.
 */
final class Iterators {
    private Iterators() { /* singleton */ }

    @SuppressWarnings("unchecked")
    public static <T> List<T> toList(Iterator<?> iterator) {
        final List<T> items = new ArrayList<>();
        while (iterator.hasNext()) {
            items.add((T) iterator.next());

        }
        return Collections.unmodifiableList(items);
    }

    @SuppressWarnings("unchecked")
    public static <T> Set<T> toSet(Iterator<?> iterator) {
        final Set<T> items = new HashSet<>();
        while (iterator.hasNext()) {
            items.add((T) iterator.next());

        }
        return Collections.unmodifiableSet(items);
    }
}
