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

import com.suryadisoft.cipher.data.CipherString;

/**
 * <code>CipherProvider</code> is a cipher provider interface to encrypt and decrypt data key and text data
 * using a master key from Key Management System (KMS) provider.
 *
 * @author Edward Suryadi
 * @since May 2025
 */
public interface CipherProvider {

    /**
     * Cipher Provider type
     */
    enum Type {
        LOCAL, // Local Provider
        GOOGLE_KMS; // Google KMS Provider
    }

    /**
     * Encrypts the plain text.
     *
     * @param plaintext Plain text
     * @return Encrypted plain text
     */
    CipherString encrypt(final byte[] plaintext);

    /**
     * Decrypts the cipher text.
     *
     * @param cipherText Encrypted text
     * @return Plain text
     */
    byte[] decrypt(final CipherString cipherText);

    /**
     * Hashes the plain text with predefined salt.
     *
     * @param plainText Plain text
     * @return Hashed plain text
     */
    String hash(final String plainText, final String salt);

    /**
     * Return the cipher provider type.
     *
     * @return {@link Type} instance
     */
    Type providerType();

    /**
     * Return the master key info.
     *
     * @return Master key info in json format
     */
    String getMasterKeyInfo();

}
