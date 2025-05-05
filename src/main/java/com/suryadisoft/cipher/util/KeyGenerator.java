/*
 * Copyright (c) 2025, Suryadisoft, Inc. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the Apache License version 2.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the Apache License version 2 for
 * more details (a copy is included in the LICENSE file that accompanied this code).
 */
package com.suryadisoft.cipher.util;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * <code>CipherKeyFactory</code> is a factory class to create new data key.
 *
 * @author Edward Suryadi
 * @since May 2025
 */
public class KeyGenerator {

    /**
     * Creates a new data key.
     *
     * @return {@link Key} instance
     *
     * @throws NoSuchAlgorithmException when algorithm is not supported
     */
    static public Key createDataKey(final String algorithm) throws NoSuchAlgorithmException {
        final javax.crypto.KeyGenerator keyGen = javax.crypto.KeyGenerator.getInstance(algorithm);
        final SecureRandom secRandom = SecureRandom.getInstanceStrong();
        keyGen.init(secRandom);

        return keyGen.generateKey();
    }

    /**
     * Transform bytes array data key into {@link Key} instance.
     *
     * @param key {@link Key} instance
     *
     * @return {@link Key} instance
     */
    static public Key createDataKey(final byte[] key, final String algorithm) {
        return new SecretKeySpec(key, 0, key.length, algorithm);
    }

    /**
     * Creates a new data key IV.
     *
     * @param size Data key IV length
     *
     * @return Data key IV in bytes array
     */
    static public byte[] createDataKeyIv(final int size) {
        final SecureRandom secRandom = new SecureRandom();
        final byte[] iv = new byte[size];
        secRandom.nextBytes(iv);

        return iv;
    }

}
