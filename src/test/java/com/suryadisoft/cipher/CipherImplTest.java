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
package com.suryadisoft.cipher;

import com.suryadisoft.cipher.data.CipherData;
import com.suryadisoft.cipher.util.CipherUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * <code>CipherImplTest</code> class is a unit-test for {@link CipherImpl} implementation class.
 *
 * @author Edward Suryadi
 * @since May 2025
 */
@Execution(ExecutionMode.CONCURRENT)
class CipherImplTest {

    private Cipher cipher;

    @BeforeEach
    void setUp() {
        this.cipher = new CipherImpl();
    }

    /**
     * Test method for {@link CipherImpl#encrypt(byte[])}.
     */
    @Test
    void testEncrypt() {
        CipherData payload = this.cipher.encrypt("Hello World!".getBytes());
        assertNotNull(payload);
        assertNotNull(payload.dataKey());
        assertNotNull(payload.cipherText());
    }

    /**
     * Test method for {@link CipherImpl#decrypt(CipherData)}.
     */
    @Test
    void testDecrypt() {
        CipherData payload = this.cipher.encrypt("Hello World!".getBytes());
        String plaintext = new String(this.cipher.decrypt(payload));
        assertNotNull(plaintext);
        assertEquals("Hello World!", plaintext);
    }

    /**
     * Test method for {@link CipherImpl#hash(String, String)}.
     */
    @Test
    void testHash() throws NoSuchAlgorithmException {
        String salt = CipherUtil.generateNewSalt();
        String hash = this.cipher.hash("Hello World!", salt);
        assertNotNull(hash);
        String hash2 = this.cipher.hash("Hello World!", salt);
        assertNotNull(hash2);
        assertEquals(hash, hash2);
    }

}
