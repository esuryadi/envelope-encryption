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

import java.util.Properties;

/**
 * <code>CipherConfig</code> is a cipher data model that stores the Cipher configuration values.
 *
 * @author Edward Suryadi
 * @since May 2025
 */
public record CipherConfig(String transformation, String algorithm, String hashAlgorithm) {
    public CipherConfig() {
        this("AES/GCM/NoPadding", "AES", "SHA3-256");
    }

    static public CipherConfig valueOf(final Properties properties) {
        final CipherConfig config = new CipherConfig();
        return new CipherConfig(properties.getProperty("transformation", config.transformation())
                , properties.getProperty("algorithm", config.algorithm())
                , properties.getProperty("hashAlgorithm", config.hashAlgorithm()));
    }
}
