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

import com.suryadisoft.cipher.provider.LocalCipher;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import java.security.Key;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * <code>KeyGeneratorTest</code> class is a unit-test for {@link KeyGenerator} implementation class.
 *
 * @author Edward Suryadi
 * @since May 2025
 */
@Execution(ExecutionMode.CONCURRENT)
class KeyGeneratorTest {

    /**
     * Test method for {@link KeyGenerator#createDataKey(String)}.
     */
    @Test
    void testGetDataEncryptionKey() throws NoSuchAlgorithmException {
        assertNotNull(KeyGenerator.createDataKey("AES"));
    }

    /**
     * Test method for {@link KeyGenerator#createDataKeyIv(int)}.
     */
    @Test
    void testGetDataEncryptionIv() {
        assertNotNull(KeyGenerator.createDataKeyIv(16));
        assertEquals(16, KeyGenerator.createDataKeyIv(16).length);
    }

    /**
     * Test method for {@link KeyGenerator#createDataKey(byte[], String)}.
     */
    @Test
    void testGetDataEncryptionKeyByteArray() throws NoSuchAlgorithmException {
        Key key = KeyGenerator.createDataKey("AES");
        assertNotNull(KeyGenerator.createDataKey(key.getEncoded(), "AES"));
        assertEquals(key, KeyGenerator.createDataKey(key.getEncoded(), "AES"));
    }

}
