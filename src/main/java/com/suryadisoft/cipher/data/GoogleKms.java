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

import com.google.cloud.kms.v1.CryptoKeyName;

import java.util.Properties;

/**
 * <code>GoogleKms</code> is a google kms configuration data model that stores google kms project id, location id,
 * key ring id, key id, and google kms api credential file.
 *
 * @author Edward Suryadi
 * @since May 2025
 */
public record GoogleKms(String projectId, String locationId, String keyRingId, String keyId, String credentialFile) {

    /**
     * Transform {@link GoogleKms} into {@link CryptoKeyName} instance.
     *
     * @return {@link CryptoKeyName} instance
     */
    public CryptoKeyName cryptoKeyName() {
        try {
            return CryptoKeyName.of(this.projectId, this.locationId, this.keyRingId, this.keyId);
        } catch (Exception e) {
            throw new RuntimeException("Unable to create Google KMS CryptoKeyName", e);
        }
    }

    /**
     * Transform java {@link Properties} into {@link GoogleKms} instance.
     *
     * @param properties Google kms configuration properties
     * @return {@link GoogleKms} instance
     */
    static public GoogleKms valueOf(final Properties properties) {
        final String projectId = properties.getProperty("projectId");
        final String locationId = properties.getProperty("locationId");
        final String keyRingId = properties.getProperty("keyRingId");
        final String keyId = properties.getProperty("keyId");
        final String credentialFile = properties.getProperty("credentialFile");

        return new GoogleKms(projectId, locationId, keyRingId, keyId, credentialFile);
    }

}
