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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * <code>CipherString</code> splits encrypted data key and encrypted text in 2 separate {@link String}.
 *
 * @author Edward Suryadi
 * @since May 2025
 */
public record CipherString(String base64DataKey, String base64CipherText) {

    /**
     * Transform encrypted string into {@link CipherString} instance.
     *
     * @param cipherText Encrypted Text
     *
     * @return {@link CipherString} instance
     */
    static public CipherString valueOf(String cipherText) {
        final Pattern cipherTextPattern = Pattern.compile("\\{(.*)}(.*)");
        final Matcher cipher = cipherTextPattern.matcher(cipherText);
        if (cipher.find()) {
            return new CipherString(cipher.group(1), cipher.group(2));
        } else {
            throw new CipherException("Invalid cipher text format!");
        }
    }

    @Override
    public String toString() {
        return "{" + this.base64DataKey + "}" + this.base64CipherText;
    }
}
