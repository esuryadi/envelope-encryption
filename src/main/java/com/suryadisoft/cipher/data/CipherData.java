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

import java.io.Serializable;

/**
 * <code>CipherData</code> is a cipher data model that stores the data encryption key and the encrypted text.
 *
 * @author Edward Suryadi
 * @since May 2025
 */
public record CipherData(CipherKey dataKey, byte[] cipherText) implements Serializable {
}
