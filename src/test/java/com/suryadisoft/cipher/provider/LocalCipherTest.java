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
package com.suryadisoft.cipher.provider;

import com.suryadisoft.cipher.Cipher;
import com.suryadisoft.cipher.CipherImpl;
import com.suryadisoft.cipher.data.CipherData;
import com.suryadisoft.cipher.data.CipherString;
import com.suryadisoft.cipher.util.CipherUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.mockito.internal.verification.Times;

import java.security.NoSuchAlgorithmException;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.*;

/**
 * <code>LocalCipherTest</code> class is a unit-test for {@link LocalCipher} implementation class.
 *
 * @author Edward Suryadi
 * @since May 2025
 */
@Execution(ExecutionMode.CONCURRENT)
class LocalCipherTest {

    private static CipherProvider localCipher;
    private static Cipher cipher;

    @BeforeAll
    static void setup() {
        Properties properties = new Properties();
        properties.setProperty("masterKey", CipherUtil.generateNewKey("AES"));
        cipher = spy(new CipherImpl());
        localCipher = new LocalCipher(cipher, properties);
    }

    @Test
    void testEncrypt() {
        CipherString cipherText = localCipher.encrypt("Hello World".getBytes());
        assertNotNull(cipherText);
    }

    @Test
    void testDecrypt() {
        CipherString cipherText = localCipher.encrypt("Hello World".getBytes());
        assertNotNull(cipherText);
        byte[] plainText = localCipher.decrypt(cipherText);
        assertNotNull(plainText);
        assertEquals("Hello World", new String(plainText));
        verify(cipher, times(2)).decrypt(isA(CipherData.class));
        plainText = localCipher.decrypt(cipherText);
        assertNotNull(plainText);
        assertEquals("Hello World", new String(plainText));
        verify(cipher, times(3)).decrypt(isA(CipherData.class));
    }

    @Test
    void testHash() throws NoSuchAlgorithmException {
        String salt = CipherUtil.generateNewSalt();
        String hash1 = localCipher.hash("Hello World", salt);
        String hash2 = localCipher.hash("Hello World", salt);
        String hash3 = localCipher.hash("Hello World", CipherUtil.generateNewSalt());
        assertNotNull(hash1);
        assertNotNull(hash2);
        assertNotNull(hash3);
        assertEquals(hash1, hash2);
        assertNotEquals(hash1, hash3);
    }

    @Test
    void testProviderType() {
        assertEquals(CipherProvider.Type.LOCAL, localCipher.providerType());
    }

    @Test
    void testGetMasterInfo() {
        assertNotNull(localCipher.getMasterKeyInfo());
    }
}
