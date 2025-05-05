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
package com.suryadisoft.cipher.data;

import com.suryadisoft.cipher.exception.CipherException;
import org.apache.commons.codec.binary.Base64;

import java.io.*;

/**
 * <code>CipherKey</code> is a cipher key data model that stores encryption data key and iv.
 *
 * @author Edward Suryadi
 * @since May 2025
 */
public record CipherKey(byte[] dataKey, byte[] iv) implements Serializable {

    /**
     * Transform the {@link CipherKey} into bytes array so it can be encrypted.
     *
     * @return {@link CipherKey} in bytes array
     */
    public byte[] toBytes() {
        try (final ByteArrayOutputStream bytesStream = new ByteArrayOutputStream()) {
            try (final ObjectOutputStream objectStream = new ObjectOutputStream(bytesStream)) {
                objectStream.writeObject(this);
            }
            return bytesStream.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    /**
     * Serializes {@link CipherKey} instance into Base64 String.
     *
     * @return {@link CipherKey} instance in Base64 String
     */
    public String toBase64() {
        final StringBuilder base64DataKey = new StringBuilder();
        base64DataKey.append(Base64.encodeBase64URLSafeString(dataKey));
        base64DataKey.append(":");
        base64DataKey.append(Base64.encodeBase64URLSafeString(iv));
        return base64DataKey.toString();
    }

    /**
     * Transform Bytes array of data key into {@link CipherKey} instance.
     *
     * @param dataKey Bytes array of data key
     *
     * @return {@link CipherKey} instance
     */
    static public CipherKey valueOf(final byte[] dataKey) {
        try (final ByteArrayInputStream bytesStream = new ByteArrayInputStream(dataKey)) {
            try (final ObjectInputStream objectStream = new ObjectInputStream(bytesStream)) {
                return (CipherKey) objectStream.readObject();
            } catch (ClassNotFoundException e) {
                throw new CipherException(e);
            }
        } catch (IOException e) {
            throw new CipherException(e.getMessage(), e);
        }
    }

    /**
     * Transform base64 data key string into {@link CipherKey} instance.
     *
     * @param base64DataKey Base64 data key string
     */
    static public CipherKey valueOf(String base64DataKey) {
        String[] base64DataKeys = base64DataKey.split(":");
        byte[] dataKey = Base64.decodeBase64(base64DataKeys[0]);
        byte[] iv = Base64.decodeBase64(base64DataKeys[1]);
        return new CipherKey(dataKey, iv);
    }

}
