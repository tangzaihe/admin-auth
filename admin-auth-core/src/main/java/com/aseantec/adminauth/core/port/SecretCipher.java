package com.aseantec.adminauth.core.port;

/**
 * 敏感字段加解密 SPI（默认 AES-256-GCM：iv(12B) || ciphertext || tag(16B)）。
 *
 * <p><b>密钥轮换</b>：加密始终使用 {@link #keyVersion()} 对应的当前密钥；
 * 解密必须传入数据行上记录的 {@code key_version}，实现内部保留旧版本密钥，
 * 从而支持"新数据用新密钥、旧数据仍可解密"的平滑轮换。</p>
 */
public interface SecretCipher {

    /** 用当前密钥版本加密。 */
    byte[] encrypt(byte[] plaintext);

    /** 当前密钥版本（写入 {@code key_version} 列）。 */
    int keyVersion();

    /**
     * 用指定版本密钥解密。
     *
     * @throws IllegalArgumentException 该版本密钥不存在
     */
    byte[] decrypt(int keyVersion, byte[] ciphertext);

    /** 兼容旧调用：按当前密钥版本解密（新代码应显式传版本）。 */
    default byte[] decrypt(byte[] ciphertext) {
        return decrypt(keyVersion(), ciphertext);
    }
}
