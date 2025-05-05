/*
 * @(#)BennetCryptoEnvEncService.java 1.0 Jun 1, 2020
 */
package com.suryadisoft.cipher;

import com.suryadisoft.cipher.data.CipherConfig;
import com.suryadisoft.cipher.data.CipherData;
import com.suryadisoft.cipher.data.CipherKey;
import com.suryadisoft.cipher.exception.CipherException;
import com.suryadisoft.cipher.util.CipherUtil;
import com.suryadisoft.cipher.util.KeyGenerator;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.*;

/**
 * <code>CipherImpl</code> is a default {@link Cipher} interface implementation.
 *
 * @author Edward Suryadi
 * @since May 2025
 */
public class CipherImpl implements Cipher {

    private final CipherConfig config;

    /**
     * Creates a new instance of {@link CipherImpl}.
     */
    public CipherImpl() {
        this.config = new CipherConfig();
    }

    /**
     * Creates a new instance of {@link CipherImpl} for a given {@link CipherConfig}.
     */
    public CipherImpl(final CipherConfig config) {
        this.config = config;
    }

    @Override
    public CipherData encrypt(final byte[] unencryptedData) {
        final CipherKey key = CipherKey.valueOf(CipherUtil.generateNewKey(this.config.algorithm()));
        return encrypt(unencryptedData, key);
    }

    @Override
    public CipherData encrypt(final byte[] unencryptedData, final CipherKey cipherKey) {
        try {
            final javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(this.config.transformation());
            final GCMParameterSpec ivspec = new GCMParameterSpec(128, cipherKey.iv());
            final Key dataKey = KeyGenerator.createDataKey(cipherKey.dataKey(), this.config.algorithm());
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, dataKey, ivspec);
            final byte[] ciphertext = cipher.doFinal(unencryptedData);

            return new CipherData(cipherKey, ciphertext);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                 | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new CipherException(e.getMessage(), e);
        }
    }

    @Override
    public byte[] decrypt(final CipherData cipherData) {
        try {
            final CipherKey key = cipherData.dataKey();
            final javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(this.config.transformation());
            final byte[] iv = key.iv();
            final GCMParameterSpec ivspec = new GCMParameterSpec(128, iv);
            final Key dataKey = KeyGenerator.createDataKey(key.dataKey(), this.config.algorithm());
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, dataKey, ivspec);

            return cipher.doFinal(cipherData.cipherText());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                 | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new CipherException(e.getMessage(), e);
        }
    }

    @Override
    public String hash(final String plaintext, final String salt) {
        try {
            final MessageDigest digest = MessageDigest.getInstance(this.config.hashAlgorithm());
            digest.update(Base64.decodeBase64(salt));
            final byte[] hashbytes = digest.digest(plaintext.getBytes(StandardCharsets.UTF_8));

            return Base64.encodeBase64URLSafeString(hashbytes);
        } catch (NoSuchAlgorithmException e) {
            throw new CipherException(e.getMessage(), e);
        }

    }

}
