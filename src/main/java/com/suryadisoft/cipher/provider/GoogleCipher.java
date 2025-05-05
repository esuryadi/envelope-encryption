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
import com.google.api.gax.core.FixedCredentialsProvider;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.kms.v1.*;
import com.google.common.annotations.VisibleForTesting;
import com.google.protobuf.ByteString;
import com.suryadisoft.cipher.Cipher;
import com.suryadisoft.cipher.data.CipherData;
import com.suryadisoft.cipher.data.CipherKey;
import com.suryadisoft.cipher.data.GoogleKms;
import com.suryadisoft.cipher.exception.CipherException;
import org.apache.commons.codec.binary.Base64;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * <code>GoogleCipher</code> is a Google KMS provider implementation.
 *
 * @author Edward Suryadi
 * @since May 2025
 */
public class GoogleCipher implements CipherProvider {

    private final Cipher cipher;
    private final GoogleKms googleKms;

    private KeyManagementServiceClient kmsClient;

    private CipherKey dataKey;

    /**
     * Creates an instance of {@link GoogleCipher} given google kms configuration and cipher instance.
     * 
     * @param googleKms {@link GoogleKms} configuration
     * @param cipher {@link Cipher} instance
     */
    public GoogleCipher(final GoogleKms googleKms, final Cipher cipher) {
        this.googleKms = googleKms;
        this.cipher = cipher;
    }

    /**
     * Creates and retrieves the {@link KeyManagementServiceClient} instance.
     * 
     * @return {@link KeyManagementServiceClient} instance
     */
    protected synchronized KeyManagementServiceClient kmsClient() {
        if (this.kmsClient == null) {
            try {
                final GoogleCredentials credentials =
                        GoogleCredentials.fromStream(Objects.requireNonNull(ClassLoader.getSystemResourceAsStream(this.googleKms.credentialFile())));
                final KeyManagementServiceSettings settings = KeyManagementServiceSettings.newBuilder()
                        .setCredentialsProvider(FixedCredentialsProvider.create(credentials)).build();

                this.kmsClient = KeyManagementServiceClient.create(settings);
            } catch (Exception e) {
                throw new CipherException("Unable to create Google KMS client", e);
            }
        }
        return this.kmsClient;
    }

    @VisibleForTesting
    protected void setDataKey(final CipherKey dataKey) {
        this.dataKey = dataKey;
    }

    @Override
    public String encrypt(final String plaintext) {
        // If the data key is set, encrypt using a given data key
        final CipherData cipherData = Objects.isNull(this.dataKey) ? cipher.encrypt(plaintext.getBytes()) : cipher.encrypt(plaintext.getBytes(), this.dataKey);
        final CipherKey dataKey = cipherData.dataKey();
        final CryptoKeyName cryptoKeyName = this.googleKms.cryptoKeyName();
        final ByteString dataKeyByteStr = ByteString.copyFromUtf8(dataKey.toBase64());
        // Encrypt the data key in google kms
        final EncryptResponse dataKeyResp = kmsClient().encrypt(cryptoKeyName, dataKeyByteStr);
        final String encryptedDataKey = Base64.encodeBase64URLSafeString(dataKeyResp.getCiphertext().toByteArray());
        final String cipherText = Base64.encodeBase64URLSafeString(cipherData.cipherText());

        return "{" + encryptedDataKey + "}" + cipherText;
    }

    @Override
    public String decrypt(final String cipherText) {
        final Pattern cipherTextPattern = Pattern.compile("\\{(.*)}(.*)");
        // Parse the encrypted text
        final Matcher cipher = cipherTextPattern.matcher(cipherText);
        if (cipher.find()) {
            // Retrieve the base64 encrypted data key
            final ByteString encryptedDataKey = ByteString.copyFrom(Base64.decodeBase64(cipher.group(1).getBytes()));
            // Retrieve the encrypted text
            final byte[] encryptedText = Base64.decodeBase64(cipher.group(2));
            // Decrypt the data key
            final DecryptResponse dataKeyResp = kmsClient().decrypt(this.googleKms.cryptoKeyName(), encryptedDataKey);
            final String dataKeyStr = dataKeyResp.getPlaintext().toStringUtf8();
            // Parse the decrypted data key
            final CipherKey dataKey = CipherKey.valueOf(dataKeyStr);
            return new String(this.cipher.decrypt(new CipherData(dataKey, encryptedText)));
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
        return Type.GOOGLE_KMS;
    }

    @Override
    public String getMasterKeyInfo() {
        try {
            final Map<String, String> masterKeyInfo = new HashMap<String, String>();
            masterKeyInfo.put("provider", providerType().name());
            masterKeyInfo.put("projectId", this.googleKms.projectId());
            masterKeyInfo.put("keyId", this.googleKms.keyId());
            masterKeyInfo.put("keyRingId", this.googleKms.keyRingId());
            masterKeyInfo.put("locationId", this.googleKms.locationId());
            final ObjectMapper objectMapper = new ObjectMapper();
            return objectMapper.writeValueAsString(masterKeyInfo);
        } catch (JsonProcessingException e) {
            return null;
        }
    }

}
