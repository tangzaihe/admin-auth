package com.aseantec.adminauth.core.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AesGcmSecretCipherTest {

    private final AesGcmSecretCipher cipher = new AesGcmSecretCipher(AesGcmSecretCipher.randomKey(), 1);

    @Test
    @DisplayName("AES-256-GCM 加解密往返，密文为 iv(12) + ct + tag(16)")
    void roundTrip() {
        byte[] plain = "EMP000123".getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = cipher.encrypt(plain);
        assertThat(encrypted.length).isEqualTo(12 + plain.length + 16);
        assertThat(encrypted).isNotEqualTo(plain);
        assertThat(cipher.decrypt(encrypted)).isEqualTo(plain);
    }

    @Test
    @DisplayName("同一明文两次加密密文不同（随机 IV），但都可解密")
    void randomIv() {
        byte[] plain = "secret".getBytes(StandardCharsets.UTF_8);
        byte[] a = cipher.encrypt(plain);
        byte[] b = cipher.encrypt(plain);
        assertThat(Arrays.equals(a, b)).isFalse();
        assertThat(cipher.decrypt(a)).isEqualTo(plain);
        assertThat(cipher.decrypt(b)).isEqualTo(plain);
    }

    @Test
    @DisplayName("篡改密文/IV 触发 GCM 校验失败")
    void tamperDetection() {
        byte[] encrypted = cipher.encrypt("hello".getBytes(StandardCharsets.UTF_8));
        byte[] tampered = encrypted.clone();
        tampered[tampered.length - 1] ^= 0x01;
        assertThatThrownBy(() -> cipher.decrypt(tampered)).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> cipher.decrypt(new byte[10])).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("密钥必须为 32 字节")
    void keyLength() {
        assertThatThrownBy(() -> new AesGcmSecretCipher(new byte[16], 1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("32 字节");
    }

    @Test
    @DisplayName("密钥轮换：旧版本密文可用 key_version 解密，新数据用新版本加密")
    void keyRotation() {
        byte[] key1 = AesGcmSecretCipher.randomKey();
        byte[] key2 = AesGcmSecretCipher.randomKey();
        AesGcmSecretCipher oldCipher = new AesGcmSecretCipher(key1, 1);
        byte[] oldCipherText = oldCipher.encrypt("EMP000123".getBytes(StandardCharsets.UTF_8));

        AesGcmSecretCipher rotated = new AesGcmSecretCipher(2, java.util.Map.of(1, key1, 2, key2));
        // 旧数据按行上的版本 1 解密
        assertThat(rotated.decrypt(1, oldCipherText))
                .isEqualTo("EMP000123".getBytes(StandardCharsets.UTF_8));
        // 新数据用当前版本 2 加密，且用版本 1 解不开
        byte[] newCipherText = rotated.encrypt("EMP000456".getBytes(StandardCharsets.UTF_8));
        assertThat(rotated.decrypt(2, newCipherText))
                .isEqualTo("EMP000456".getBytes(StandardCharsets.UTF_8));
        assertThatThrownBy(() -> rotated.decrypt(1, newCipherText))
                .isInstanceOf(IllegalStateException.class);
        // 未知版本直接报错
        assertThatThrownBy(() -> rotated.decrypt(9, newCipherText))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("未知的密钥版本");
    }
}
