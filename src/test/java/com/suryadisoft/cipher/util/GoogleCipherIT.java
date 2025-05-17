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

import com.suryadisoft.cipher.provider.CipherProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import java.security.NoSuchAlgorithmException;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

/**
 * <code>CipherUtilIT</code> class is a integration-test for {@link CipherUtil} implementation class.
 *
 * @author Edward Suryadi
 * @since May 2025
 */
@Execution(ExecutionMode.CONCURRENT)
public class GoogleCipherIT {

    static CipherUtil googleCipher;

    @BeforeAll
    static void setup() {
        Properties properties = new Properties();
        properties.setProperty("gcpProjectId", "envelope-encryption-458913");
        properties.setProperty("gcpLocationId", "us-west2");
        properties.setProperty("gcpKeyRingId", "suryadisoft");
        properties.setProperty("gcpKeyId", "EdwardKey");
        properties.setProperty("gcpCredentialFile", "envelope-encryption-458913-0bafc4c17237.json");
        googleCipher = CipherUtil.getInstance(CipherProvider.Type.GOOGLE_KMS, properties);
    }

    @Test
    void testEncrypt() {
        String cipherText = googleCipher.encrypt("Hello World");
        assertNotNull(cipherText);
    }

    @Test
    void testDecrypt() {
        String cipherText = googleCipher.encrypt("Hello World");
        assertNotNull(cipherText);
        String plainText = new String(googleCipher.decrypt(cipherText));
        assertNotNull(plainText);
        assertEquals("Hello World", plainText);
    }

    @Test
    void testHash() throws NoSuchAlgorithmException {
        String salt = CipherUtil.generateNewSalt();
        String hash1 = googleCipher.hash("Hello World", salt);
        String hash2 = googleCipher.hash("Hello World", salt);
        String hash3 = googleCipher.hash("Hello World", CipherUtil.generateNewSalt());
        assertNotNull(hash1);
        assertNotNull(hash2);
        assertNotNull(hash3);
        assertEquals(hash1, hash2);
        assertNotEquals(hash1, hash3);
    }
}
