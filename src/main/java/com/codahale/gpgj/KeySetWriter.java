package com.codahale.gpgj;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * A writer for {@link KeySet}s.
 */
public class KeySetWriter {
    /**
     * Write the given key set to the given output stream.
     *
     * @param keySet a key set
     * @param output an output stream
     * @throws IOException if there is an error writing to {@code output}
     */
    public void write(KeySet keySet, OutputStream output) throws IOException {
        keySet.getMasterKey().getSecretKey().encode(output);
        keySet.getSubKey().getSecretKey().encode(output);
    }

    /**
     * Convert the given key set to a byte array.
     *
     * @param keySet a key set
     * @return {@code keySet} as a byte array
     */
    public byte[] toByteArray(KeySet keySet) {
        try {
            final ByteArrayOutputStream output = new ByteArrayOutputStream();
            write(keySet, output);
            return output.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
