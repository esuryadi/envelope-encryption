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
import com.suryadisoft.cipher.data.CipherKey;

/**
 * <code>Cipher</code> is an envelope encryption interface for encrypting plain text and decrypting encrypted text
 * using data key of each encrypted text.
 *
 * @author Edward Suryadi
 * @since May 2025
 */
public interface Cipher {

    /**
     * Encrypt a bytes array value.
     *
     * @param unencryptedData Unencrypted bytes array data
     *
     * @return {@link CipherData} instance
     */
    CipherData encrypt(final byte[] unencryptedData);

    /**
     * Encrypt a bytes array value with a given {@link CipherKey}.
     *
     * @param unencryptedData Unencrypted bytes array data
     * @param cipherKey {@link CipherKey} instance
     *
     * @return {@link CipherData} instance
     */
    CipherData encrypt(final byte[] unencryptedData, final CipherKey cipherKey);

    /**
     * Decrypt a given {@link CipherData} instance.
     *
     * @param cipherData {@link CipherData} instance
     *
     * @return Decrypted {@link CipherData} instance in bytes array
     */
    byte[] decrypt(final CipherData cipherData);

    /**
     * Create a hash string of a given plaintext and salt.
     *
     * @param plaintext Plain text value
     * @param salt      Bennet Crypto salt
     *
     * @return Hash string
     */
    String hash(final String plaintext, final String salt);

}
