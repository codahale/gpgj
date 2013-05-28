package com.codahale.gpgj;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.util.concurrent.atomic.AtomicBoolean;

class BCTest {
    private static final AtomicBoolean LOADED = new AtomicBoolean();
    static {
        // load the BC provider once and only once
        if (LOADED.compareAndSet(false, true)) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
}
