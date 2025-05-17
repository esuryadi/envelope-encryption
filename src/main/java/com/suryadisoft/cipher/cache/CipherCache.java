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

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.suryadisoft.cipher.data.CipherKey;

import java.util.concurrent.TimeUnit;
import java.util.function.Function;

/**
 * <code>CipherCache</code> is a cache that stores unencrypted data key in local memory so data key decryption can
 * be skipped for short period of time in order to improve decryption performance.
 *
 * @author Edward Suryadi
 * @since May 2025
 */
public class CipherCache {
    LoadingCache<String, CipherKey> cipherCache;

    /**
     * Creates an instance of {@link CipherCache} for given {@link CacheConfig} and data key decryption function.
     *
     * @param cacheConfig {@link CacheConfig} instance
     * @param dataKeyFunc Data key decryption function
     */
    public CipherCache(final CacheConfig cacheConfig, final Function<String, CipherKey> dataKeyFunc) {
        final CacheLoader<String, CipherKey> cacheLoader = new CacheLoader<>() {
            @Override
            public CipherKey load(final String key) throws Exception {
                return dataKeyFunc.apply(key);
            }
        };
        this.cipherCache = CacheBuilder.newBuilder()
                .initialCapacity(cacheConfig.initialCapacity())
                .concurrencyLevel(cacheConfig.concurrencyLevel())
                .maximumSize(cacheConfig.maximumSize())
                .expireAfterAccess(cacheConfig.expireDuration(), TimeUnit.MILLISECONDS)
                .build(cacheLoader);
    }

    /**
     * Gets the unencrypted data key from cache for a given encrypted data key.
     *
     * @param encryptedDataKey Encrypted data key string
     *
     * @return {@link CipherKey} instance
     */
    public CipherKey getDataKey(String encryptedDataKey) {
        return this.cipherCache.getUnchecked(encryptedDataKey);
    }
}
