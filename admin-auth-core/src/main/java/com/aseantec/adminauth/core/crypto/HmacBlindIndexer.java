package com.aseantec.adminauth.core.crypto;

import com.aseantec.adminauth.core.domain.IdentityType;
import com.aseantec.adminauth.core.port.BlindIndexer;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HexFormat;

/** HMAC-SHA256 盲索引：{@code HMAC(indexKey, "TYPE|normalized|v1")} → 32 字节。 */
public class HmacBlindIndexer implements BlindIndexer {

    private final byte[] key;

    public HmacBlindIndexer(byte[] key) {
        if (key == null || key.length < 16) {
            throw new IllegalArgumentException("盲索引密钥长度不足（至少 16 字节）");
        }
        this.key = key.clone();
    }

    @Override
    public byte[] index(IdentityType type, String normalizedValue) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            String payload = type.name() + "|" + normalizedValue + "|v1";
            return mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("盲索引计算失败", e);
        }
    }

    /** 测试用十六进制展示（不可用于生产日志）。 */
    public String indexHex(IdentityType type, String normalizedValue) {
        return HexFormat.of().formatHex(index(type, normalizedValue));
    }
}
