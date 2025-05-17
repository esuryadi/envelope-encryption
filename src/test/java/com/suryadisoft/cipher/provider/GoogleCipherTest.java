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

import com.google.cloud.kms.v1.CryptoKeyName;
import com.google.cloud.kms.v1.DecryptResponse;
import com.google.cloud.kms.v1.EncryptResponse;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.protobuf.ByteString;
import com.suryadisoft.cipher.CipherImpl;
import com.suryadisoft.cipher.data.CipherKey;
import com.suryadisoft.cipher.data.CipherString;
import com.suryadisoft.cipher.data.GoogleKms;
import com.suryadisoft.cipher.util.CipherUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import java.security.NoSuchAlgorithmException;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * <code>GoogleCipherTest</code> class is a unit-test for {@link GoogleCipher} implementation class.
 *
 * @author Edward Suryadi
 * @since May 2025
 */
@Execution(ExecutionMode.CONCURRENT)
class GoogleCipherTest {

    private static GoogleCipher googleCipher;

    @BeforeAll
    static void setup() {
        final String dataKey = CipherUtil.generateNewKey("AES");
        final KeyManagementServiceClient kmsClient = mock(KeyManagementServiceClient.class);
        final EncryptResponse encryptResp = mock(EncryptResponse.class);
        final ByteString cipherText = ByteString.copyFromUtf8(dataKey);
        when(encryptResp.getCiphertext()).thenReturn(cipherText);
        when(kmsClient.encrypt(isA(CryptoKeyName.class), isA(ByteString.class))).thenReturn(encryptResp);
        final DecryptResponse decryptResponse = mock(DecryptResponse.class);
        when(decryptResponse.getPlaintext()).thenReturn(cipherText);
        when(kmsClient.decrypt(isA(CryptoKeyName.class), isA(ByteString.class))).thenReturn(decryptResponse);
        googleCipher = new GoogleCipher(new CipherImpl(), kmsClient, new Properties());
        googleCipher.setDataKey(CipherKey.valueOf(dataKey));
    }

    @Test
    void testEncrypt() {
        CipherString cipherText = googleCipher.encrypt("Hello World".getBytes());
        assertNotNull(cipherText);
    }

    @Test
    void testDecrypt() {
        CipherString cipherText = googleCipher.encrypt("Hello World".getBytes());
        assertNotNull(cipherText);
        byte[] plainText = googleCipher.decrypt(cipherText);
        assertNotNull(plainText);
        assertEquals("Hello World", new String(plainText));
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

    @Test
    void testProviderType() {
        assertEquals(CipherProvider.Type.GOOGLE_KMS, googleCipher.providerType());
    }

    @Test
    void testGetMasterInfo() {
        assertNotNull(googleCipher.getMasterKeyInfo());
    }
}
