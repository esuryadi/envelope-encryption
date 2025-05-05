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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.suryadisoft.cipher.Cipher;
import com.suryadisoft.cipher.data.CipherData;
import com.suryadisoft.cipher.data.CipherKey;
import com.suryadisoft.cipher.exception.CipherException;
import org.apache.commons.codec.binary.Base64;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * <code>GoogleCipher</code> is a Google KMS provider implementation.
 *
 * @author Edward Suryadi
 * @since May 2025
 */
public class LocalCipher implements CipherProvider {

    private final Cipher cipher;
    private final CipherKey masterKey;

    public LocalCipher(final Cipher cipher, final String masterKey) {
        this.cipher = cipher;
        this.masterKey = CipherKey.valueOf(masterKey);
    }

    @Override
    public String encrypt(String plaintext) {
        // Encrypt the plain text
        final CipherData cipherData = this.cipher.encrypt(plaintext.getBytes());
        // Get the data key that is created
        final CipherKey dataKey = cipherData.dataKey();
        // Encrypt the data key with master key
        final CipherData encryptedDataKey = this.cipher.encrypt(dataKey.toBytes(), this.masterKey);
        // Convert the encrypted String to base64 string
        final String encryptedDataKeyBase64Str = Base64.encodeBase64URLSafeString(encryptedDataKey.cipherText());

        return "{" + encryptedDataKeyBase64Str + "}" + Base64.encodeBase64URLSafeString(cipherData.cipherText());
    }

    @Override
    public String decrypt(String cipherText) {
        final Pattern cipherTextPattern = Pattern.compile("\\{(.*)}(.*)");
        // Parse the encrypted text
        final Matcher cipher = cipherTextPattern.matcher(cipherText);
        if (cipher.find()) {
            // Decode the base64 encrypted data key
            final byte[] encryptedDataKey = Base64.decodeBase64(cipher.group(1));
            // Retrieve the encrypted text
            final byte[] encryptedText = Base64.decodeBase64(cipher.group(2));
            // Decrypt the data key
            final byte[] dataKey = this.cipher.decrypt(new CipherData(this.masterKey, encryptedDataKey));
            // Transform into CipherKey
            final CipherKey cipherKey = CipherKey.valueOf(dataKey);
            return new String(this.cipher.decrypt(new CipherData(cipherKey, encryptedText)));
        } else {
            throw new CipherException("Invalid cipher text format!");
        }
    }

    @Override
    public String hash(final String plaintext, final String salt) {
        return this.cipher.hash(plaintext, salt);
    }

    @Override
    public Type providerType() {
        return Type.LOCAL;
    }

    @Override
    public String getMasterKeyInfo() {
        try {
            final Map<String, String> masterKeyInfo = new HashMap<String, String>();
            masterKeyInfo.put("provider", providerType().name());
            final ObjectMapper objectMapper = new ObjectMapper();
            return objectMapper.writeValueAsString(masterKeyInfo);
        } catch (JsonProcessingException e) {
            return null;
        }
    }

}
