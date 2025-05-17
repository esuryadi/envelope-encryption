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
package com.suryadisoft.cipher.cache;

import java.util.Properties;

/**
 * <code>CacheConfig</code> stores the Cipher cache configuration values.
 *
 * @author Edward Suryadi
 * @since May 2025
 */
public record CacheConfig(int initialCapacity, int concurrencyLevel, int maximumSize, long expireDuration) {
    public CacheConfig() {
        this(16, 4, 100, 10000);
    }

    /**
     * Transform cache configuration properties into {@link CacheConfig} record instance.
     *
     * @param properties {@link Properties} configuration
     *
     * @return {@link CacheConfig} record instance
     */
    static public CacheConfig valueOf(final Properties properties) {
        final CacheConfig cacheConfig = new CacheConfig();
        return new CacheConfig(Integer.parseInt(properties.getProperty("initialCapacity", String.valueOf(cacheConfig.initialCapacity())))
                , Integer.parseInt(properties.getProperty("concurrencyLevel", String.valueOf(cacheConfig.concurrencyLevel())))
                , Integer.parseInt(properties.getProperty("maximumSize", String.valueOf(cacheConfig.maximumSize())))
                , Long.parseLong(properties.getProperty("expireDuration", String.valueOf(cacheConfig.expireDuration()))));
    }
}
