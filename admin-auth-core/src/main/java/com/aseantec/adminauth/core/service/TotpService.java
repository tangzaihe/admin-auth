package com.aseantec.adminauth.core.service;

import com.aseantec.adminauth.core.util.Base32;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Locale;

/**
 * TOTP（RFC 6238）：HMAC-SHA1 / 默认 6 位 / 30s 时间步，支持 ±window 容错与恒定时间比较。
 * <p>Base32 编解码见 {@link Base32}；默认密钥 20 字节（160 bit，与 RFC 4226 一致）。</p>
 */
public class TotpService {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int DEFAULT_SECRET_BYTES = 20;

    /** 生成随机共享密钥（20 字节）。 */
    public byte[] randomSecret() {
        byte[] secret = new byte[DEFAULT_SECRET_BYTES];
        RANDOM.nextBytes(secret);
        return secret;
    }

    public String encodeBase32(byte[] secret) {
        return Base32.encode(secret);
    }

    public byte[] decodeBase32(String base32) {
        return Base32.decode(base32);
    }

    /**
     * 计算指定 Unix 秒（UTC）的 TOTP。
     *
     * @param secret      共享密钥
     * @param epochSeconds Unix 秒
     * @param digits      位数（6~8）
     * @param period      时间步长（秒）
     */
    public String generate(byte[] secret, long epochSeconds, int digits, int period) {
        if (secret == null || secret.length == 0) {
            throw new IllegalArgumentException("TOTP 密钥不能为空");
        }
        if (digits < 6 || digits > 8) {
            throw new IllegalArgumentException("TOTP 位数仅支持 6~8");
        }
        if (period <= 0) {
            throw new IllegalArgumentException("TOTP 时间步长必须为正数");
        }
        long counter = Math.floorDiv(epochSeconds, period);
        byte[] hash = hmacSha1(secret, counter);
        int offset = hash[hash.length - 1] & 0x0F;
        int binary = ((hash[offset] & 0x7F) << 24)
                | ((hash[offset + 1] & 0xFF) << 16)
                | ((hash[offset + 2] & 0xFF) << 8)
                | (hash[offset + 3] & 0xFF);
        int modulo = (int) Math.pow(10, digits);
        int otp = binary % modulo;
        return String.format(Locale.ROOT, "%0" + digits + "d", otp);
    }

    /**
     * 在 [current-window, current+window] 时间步内匹配验证码。
     *
     * @return 命中的最大时间步；未命中返回 -1
     */
    public long matchStep(byte[] secret, String code, long epochSeconds, int digits, int period, int window) {
        if (code == null) {
            return -1;
        }
        String submitted = code.replaceAll("\\s", "");
        if (submitted.isEmpty()) {
            return -1;
        }
        long current = Math.floorDiv(epochSeconds, period);
        int effectiveWindow = Math.max(0, window);
        long matched = -1;
        for (long step = current - effectiveWindow; step <= current + effectiveWindow; step++) {
            if (step < 0) {
                continue;
            }
            String expected = generate(secret, step * period, digits, period);
            if (MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),
                    submitted.getBytes(StandardCharsets.US_ASCII))) {
                matched = Math.max(matched, step);
            }
        }
        return matched;
    }

    /** 生成 otpauth:// 迁移 URI（供认证器扫码/手输）。 */
    public String otpauthUri(String issuer, String accountName, String base32Secret, int digits, int period) {
        String safeIssuer = issuer == null || issuer.isBlank() ? "Admin Auth" : issuer.trim();
        String account = accountName == null || accountName.isBlank() ? "user" : accountName.trim();
        String label = urlEncode(safeIssuer) + ":" + urlEncode(account);
        return "otpauth://totp/" + label
                + "?secret=" + base32Secret
                + "&issuer=" + urlEncode(safeIssuer)
                + "&algorithm=SHA1"
                + "&digits=" + digits
                + "&period=" + period;
    }

    private byte[] hmacSha1(byte[] secret, long counter) {
        byte[] data = new byte[8];
        long value = counter;
        for (int i = 7; i >= 0; i--) {
            data[i] = (byte) (value & 0xFF);
            value >>= 8;
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(secret, "HmacSHA1"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("TOTP 计算失败", e);
        }
    }

    private String urlEncode(String value) {
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8.name()).replace("+", "%20");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }
}
