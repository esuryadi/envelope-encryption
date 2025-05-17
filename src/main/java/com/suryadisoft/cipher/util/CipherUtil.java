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

import com.suryadisoft.cipher.CipherImpl;
import com.suryadisoft.cipher.data.CipherConfig;
import com.suryadisoft.cipher.data.CipherKey;
import com.suryadisoft.cipher.data.CipherString;
import com.suryadisoft.cipher.data.GoogleKms;
import com.suryadisoft.cipher.provider.CipherProvider;
import com.suryadisoft.cipher.provider.GoogleCipher;
import com.suryadisoft.cipher.provider.LocalCipher;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.tuple.Pair;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Optional;
import java.util.Properties;

/**
 * <code>CipherUtil</code> is a singleton utility class to encrypt, decrypt and hash data using the envelope
 * encryption algorithm given the kms provider.
 *
 * @author Edward Suryadi
 * @since May 2025
 */
public class CipherUtil {

    private static CipherUtil _INSTANCE;

    private final CipherProvider cipherProvider;
    private final Properties properties;

    /**
     * Creates an instance of {@link CipherUtil} for a given kms provider type and configuration properties.
     *
     * @param providerType KMS provider type
     * @param properties   Configuration properties
     */
    private CipherUtil(final CipherProvider.Type providerType, final Properties properties) {
        this.properties = properties;
        if (providerType == CipherProvider.Type.GOOGLE_KMS) {
            this.cipherProvider = new GoogleCipher(new CipherImpl(CipherConfig.valueOf(properties)), properties);
        } else {
            this.cipherProvider = new LocalCipher(new CipherImpl(CipherConfig.valueOf(properties)), properties);
        }
    }

    /**
     * Gets a new instance of {@link CipherUtil} instance with local kms provider and auto-generated master key.
     *
     * @return {@link CipherUtil} instance
     */
    static public CipherUtil getNewInstance() {
        final Properties properties = new Properties();
        properties.setProperty("masterKey", CipherUtil.generateNewKey(new CipherConfig().algorithm()));
        return getNewInstance(properties);
    }

    /**
     * Gets a new instance of {@link CipherUtil} instance with local kms provider for a given configuration
     * properties.
     *
     * @return {@link CipherUtil} instance
     */
    static public CipherUtil getNewInstance(final Properties properties) {
        return getNewInstance(CipherProvider.Type.LOCAL, properties);
    }

    /**
     * Gets a new instance of {@link CipherUtil} instance for a given kms provider type and configuration
     * properties.
     *
     * @return {@link CipherUtil} instance
     */
    static public CipherUtil getNewInstance(final CipherProvider.Type providerType, final Properties properties) {
        return new CipherUtil(providerType, properties);
    }

    /**
     * Gets a singleton instance of {@link CipherUtil} instance with local kms provider and auto-generated master key.
     *
     * @return {@link CipherUtil} instance
     */
    static public synchronized CipherUtil getInstance() {
        final Properties properties = new Properties();
        properties.setProperty("masterKey", CipherUtil.generateNewKey(new CipherConfig().algorithm()));
        return getInstance(properties);
    }

    /**
     * Gets a singleton instance of {@link CipherUtil} instance with local kms provider for a given configuration
     * properties.
     *
     * @return {@link CipherUtil} instance
     */
    static public synchronized CipherUtil getInstance(final Properties properties) {
        return getInstance(CipherProvider.Type.LOCAL, properties);
    }

    /**
     * Gets a singleton instance of {@link CipherUtil} instance for a given kms provider type and configuration
     * properties.
     *
     * @return {@link CipherUtil} instance
     */
    static public synchronized CipherUtil getInstance(final CipherProvider.Type providerType, final Properties properties) {
        if (_INSTANCE == null) {
            _INSTANCE = getNewInstance(providerType, properties);
        }

        return _INSTANCE;
    }

    /**
     * Gets the configuration {@link Properties}.
     *
     * @return Configuration properties
     */
    public Properties getProperties() {
        return properties;
    }

    /**
     * Encrypts the plain text.
     *
     * @param plainText Plain text
     * @return Encrypted plain text
     */
    public String encrypt(final String plainText) {
        return Optional.ofNullable(plainText).map(String::getBytes).map(this::encrypt).orElse(null);
    }

    /**
     * Encrypts the bytes array.
     *
     * @param bytes Bytes Array
     * @return Encrypted bytes array
     */
    public String encrypt(final byte[] bytes) {
        return Optional.ofNullable(bytes).map(cipherProvider::encrypt).map(CipherString::toString).orElse(null);
    }

    /**
     * Decrypts the cipher text into bytes array.
     *
     * @param cipherText Encrypted text
     * @return Bytes Array
     */
    public byte[] decrypt(final String cipherText) {
        return Optional.ofNullable(cipherText).map(CipherString::valueOf).map(cipherProvider::decrypt).orElse(null);
    }

    /**
     * Hashes the plain text with predefined salt.
     *
     * @param plainText Plain text
     * @return Hashed plain text
     */
    public String hash(final String plainText, final String salt) {
        return Pair.ofNonNull(plainText, salt).apply(cipherProvider::hash);
    }

    /**
     * Generates a new data key for a given security algorithm, e.g. "AES".
     *
     * @param algorithm the standard name of the requested key algorithm.
     * @return Data key in base64 string
     */
    static public String generateNewKey(final String algorithm) {
        byte[] newDataKey = null;
        try {
            newDataKey = KeyGenerator.createDataKey(algorithm).getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
        final byte[] iv = KeyGenerator.createDataKeyIv(16);
        final CipherKey key = new CipherKey(newDataKey, iv);
        return key.toBase64();
    }

    /**
     * Generates a new hashing salt.
     *
     * @return Hash Salt string
     * @throws NoSuchAlgorithmException if Algorithm is invalid
     */
    static public String generateNewSalt() throws NoSuchAlgorithmException {
        final SecureRandom secureRandom = SecureRandom.getInstanceStrong();
        final byte[] salt = new byte[16];
        secureRandom.nextBytes(salt);

        return Base64.encodeBase64URLSafeString(salt);
    }

}
