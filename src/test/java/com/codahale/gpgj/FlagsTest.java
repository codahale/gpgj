package com.codahale.gpgj;

import org.junit.Test;

import java.util.Arrays;

import static org.fest.assertions.api.Assertions.assertThat;
import static org.fest.assertions.api.Assertions.failBecauseExceptionWasNotThrown;

public class FlagsTest {
    private static enum Letter implements Flag {
        A(1), B(2), C(4);

        private final int value;

        private Letter(int value) {
            this.value = value;
        }

        @Override
        public int value() {
            return value;
        }
    }

    @Test
    public void convertsCollectionsOfFlagsToArraysOfInts() throws Exception {
        assertThat(Flags.toIntArray(Arrays.asList(Letter.A, Letter.C)))
                .isEqualTo(new int[]{1, 4});
    }

    @Test
    public void convertsSetsOfFlagsToBitmasks() throws Exception {
        assertThat(Flags.toBitmask(Arrays.asList(Letter.B, Letter.C)))
                .isEqualTo(6);
    }

    @Test
    public void convertsIntsToInstances() throws Exception {
        assertThat(Flags.fromInt(Letter.class, 2))
                .isEqualTo(Letter.B);
    }

    @Test
    public void convertingIntsThrowsAnIllegalArgumentExceptionIfTheValueHasNoCorrespondingInstance() throws Exception {
        try {
            Flags.fromInt(Letter.class, 18);
            failBecauseExceptionWasNotThrown(IllegalArgumentException.class);
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage())
                    .isEqualTo("No enum constant of class com.codahale.gpgj.FlagsTest$Letter exists with value 18");
        }
    }

    @Test
    public void convertsIntArraysToInstances() throws Exception {
        assertThat(Flags.fromIntArray(Letter.class, new int[]{1, 4}))
                .containsOnly(Letter.A, Letter.C);
    }

    @Test
    public void convertsBitmasksToInstances() throws Exception {
        assertThat(Flags.fromBitmask(Letter.class, 6))
                .containsOnly(Letter.B, Letter.C);
    }
}
