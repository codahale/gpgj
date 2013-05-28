package com.codahale.gpgj;

import org.junit.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.fest.assertions.api.Assertions.assertThat;

public class IteratorsTest {
    @Test
    public void convertsIteratorsIntoAList() throws Exception {
        final List<String> numbers = Arrays.asList("one", "two", "three");
        final List<String> otherNumbers = Iterators.toList(numbers.iterator());
        assertThat(otherNumbers)
                .isEqualTo(numbers);
    }

    @Test
    public void convertsIteratorsIntoASet() throws Exception {
        final Set<String> numbers = new HashSet<>(Arrays.asList("one", "two", "three"));
        final Set<String> otherNumbers = Iterators.toSet(numbers.iterator());
        assertThat(otherNumbers)
                .isEqualTo(numbers);
    }
}
