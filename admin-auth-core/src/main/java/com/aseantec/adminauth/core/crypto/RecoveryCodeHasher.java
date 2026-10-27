package com.aseantec.adminauth.core.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HexFormat;
import java.util.Locale;

/**
 * 恢复码哈希：{@code HMAC-SHA256(OTP_KEY, normalize(code))} 十六进制。
 * <p>恢复码为高熵随机串，无需 BCrypt 慢哈希；重点是单次使用 + 服务端密钥防彩虹表。</p>
 */
public class RecoveryCodeHasher {

    private final byte[] key;

    public RecoveryCodeHasher(byte[] key) {
        if (key == null || key.length < 16) {
            throw new IllegalArgumentException("恢复码密钥长度不足（至少 16 字节）");
        }
        this.key = key.clone();
    }

    public String hash(String code) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(normalize(code).getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("恢复码哈希失败", e);
        }
    }

    public String normalize(String code) {
        if (code == null) {
            return "";
        }
        return code.replaceAll("[^A-Za-z0-9]", "").toUpperCase(Locale.ROOT);
    }
}
