package com.aseantec.adminauth.core.crypto;

import com.aseantec.adminauth.core.port.SecretCipher;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * AES-256-GCM 实现：输出 {@code iv(12B) || ciphertext || tag(16B)}，无 AAD。
 *
 * <p>支持多版本密钥：构造时传入 {@code version -> key} 的 keyring 与当前版本，
 * {@link #encrypt} 用当前版本，{@link #decrypt(int, byte[])} 按数据行上的版本选择密钥，
 * 因此换密钥后旧数据仍可解密。纯 JDK 实现，属于 core 领域层的默认 {@link SecretCipher}。</p>
 */
public class AesGcmSecretCipher implements SecretCipher {

    private static final int KEY_LENGTH = 32;
    private static final int IV_LENGTH = 12;
    private static final int TAG_BITS = 128;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Map<Integer, SecretKeySpec> keys;
    private final int currentVersion;

    public AesGcmSecretCipher(byte[] keyBytes, int keyVersion) {
        this(keyVersion, Map.of(keyVersion, keyBytes));
    }

    public AesGcmSecretCipher(int currentVersion, Map<Integer, byte[]> keyBytesByVersion) {
        if (keyBytesByVersion == null || keyBytesByVersion.isEmpty()) {
            throw new IllegalArgumentException("AES-256 密钥环不能为空");
        }
        Map<Integer, SecretKeySpec> keyring = new HashMap<>();
        for (Map.Entry<Integer, byte[]> entry : keyBytesByVersion.entrySet()) {
            byte[] keyBytes = entry.getValue();
            if (keyBytes == null || keyBytes.length != KEY_LENGTH) {
                throw new IllegalArgumentException("AES-256 密钥必须为 32 字节（版本 " + entry.getKey()
                        + "，实际 " + (keyBytes == null ? 0 : keyBytes.length) + "）");
            }
            keyring.put(entry.getKey(), new SecretKeySpec(keyBytes.clone(), "AES"));
        }
        if (!keyring.containsKey(currentVersion)) {
            throw new IllegalArgumentException("当前密钥版本 " + currentVersion + " 未在密钥环中提供");
        }
        this.currentVersion = currentVersion;
        this.keys = Map.copyOf(keyring);
    }

    @Override
    public byte[] encrypt(byte[] plaintext) {
        if (plaintext == null) {
            throw new IllegalArgumentException("明文不能为空");
        }
        try {
            byte[] iv = new byte[IV_LENGTH];
            RANDOM.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keys.get(currentVersion), new GCMParameterSpec(TAG_BITS, iv));
            byte[] cipherText = cipher.doFinal(plaintext);
            byte[] out = new byte[IV_LENGTH + cipherText.length];
            System.arraycopy(iv, 0, out, 0, IV_LENGTH);
            System.arraycopy(cipherText, 0, out, IV_LENGTH, cipherText.length);
            return out;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM 加密失败", e);
        }
    }

    @Override
    public byte[] decrypt(int keyVersion, byte[] ciphertext) {
        SecretKeySpec key = keys.get(keyVersion);
        if (key == null) {
            throw new IllegalArgumentException("未知的密钥版本: " + keyVersion + "（请配置历史密钥 admin-auth.keys.data-kek-history）");
        }
        if (ciphertext == null || ciphertext.length < IV_LENGTH + TAG_BITS / 8) {
            throw new IllegalArgumentException("AES-GCM 密文长度非法");
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, Arrays.copyOfRange(ciphertext, 0, IV_LENGTH)));
            return cipher.doFinal(Arrays.copyOfRange(ciphertext, IV_LENGTH, ciphertext.length));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM 解密失败", e);
        }
    }

    @Override
    public int keyVersion() {
        return currentVersion;
    }

    /** 测试/示例用：生成 32 字节随机密钥。 */
    public static byte[] randomKey() {
        byte[] key = new byte[KEY_LENGTH];
        RANDOM.nextBytes(key);
        return key;
    }

    public static byte[] utf8Key(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
