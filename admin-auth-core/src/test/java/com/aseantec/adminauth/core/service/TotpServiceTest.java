package com.aseantec.adminauth.core.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * TOTP 单元测试：直接使用 RFC 6238 附录 B 的官方 SHA1 向量（8 位），
 * 以及 RFC 4648 / RFC 4226 的 Base32 向量，避免"自证"。
 */
class TotpServiceTest {

    private static final String SECRET_ASCII = "12345678901234567890";
    private static final String SECRET_BASE32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    private final TotpService totp = new TotpService();
    private final byte[] secret = SECRET_ASCII.getBytes(StandardCharsets.US_ASCII);

    @Test
    @DisplayName("RFC 6238 官方向量：TOTP-SHA1-8 位 6 组时间点")
    void rfc6238ReferenceVectors() {
        assertThat(totp.generate(secret, 59L, 8, 30)).isEqualTo("94287082");
        assertThat(totp.generate(secret, 1_111_111_109L, 8, 30)).isEqualTo("07081804");
        assertThat(totp.generate(secret, 1_111_111_111L, 8, 30)).isEqualTo("14050471");
        assertThat(totp.generate(secret, 1_234_567_890L, 8, 30)).isEqualTo("89005924");
        assertThat(totp.generate(secret, 2_000_000_000L, 8, 30)).isEqualTo("69279037");
        assertThat(totp.generate(secret, 20_000_000_000L, 8, 30)).isEqualTo("65353130");
    }

    @Test
    @DisplayName("Base32 编解码与 RFC 4648 向量一致，且可双向往返")
    void base32RoundTrip() {
        assertThat(totp.encodeBase32(secret)).isEqualTo(SECRET_BASE32);
        assertThat(totp.decodeBase32(SECRET_BASE32)).isEqualTo(secret);
        // 小写/带空格/带填充也应可解析
        assertThat(totp.decodeBase32("gezd gnbv gy3t qojq gezd gnbv gy3t qojq====")).isEqualTo(secret);
    }

    @Test
    @DisplayName("±window 命中：上一时间步与下一时间步均接受，超出窗口不接受")
    void matchingWindow() {
        long t = 1_111_111_111L;
        long step = t / 30;
        String current = totp.generate(secret, step * 30, 6, 30);
        String previous = totp.generate(secret, (step - 1) * 30, 6, 30);
        String next = totp.generate(secret, (step + 1) * 30, 6, 30);
        String tooOld = totp.generate(secret, (step - 5) * 30, 6, 30);

        assertThat(totp.matchStep(secret, current, t, 6, 30, 1)).isEqualTo(step);
        assertThat(totp.matchStep(secret, previous, t, 6, 30, 1)).isEqualTo(step - 1);
        assertThat(totp.matchStep(secret, next, t, 6, 30, 1)).isEqualTo(step + 1);
        assertThat(totp.matchStep(secret, tooOld, t, 6, 30, 1)).isEqualTo(-1L);
        assertThat(totp.matchStep(secret, "000000", t, 6, 30, 1)).isEqualTo(-1L);
        assertThat(totp.matchStep(secret, null, t, 6, 30, 1)).isEqualTo(-1L);
    }

    @Test
    @DisplayName("otpauth URI 含 issuer/secret/algorithm/digits/period，标签做 URL 编码")
    void otpauthUri() {
        String uri = totp.otpauthUri("Admin Auth", "admin@corp.example", SECRET_BASE32, 6, 30);
        assertThat(uri).startsWith("otpauth://totp/Admin%20Auth:admin%40corp.example?");
        assertThat(uri).contains("secret=" + SECRET_BASE32);
        assertThat(uri).contains("issuer=Admin%20Auth");
        assertThat(uri).contains("algorithm=SHA1");
        assertThat(uri).contains("digits=6");
        assertThat(uri).contains("period=30");
    }

    @Test
    @DisplayName("随机 secret 为 20 字节且两次生成不同")
    void randomSecret() {
        byte[] a = totp.randomSecret();
        byte[] b = totp.randomSecret();
        assertThat(a).hasSize(20);
        assertThat(a).isNotEqualTo(b);
        assertThat(totp.encodeBase32(a)).hasSize(32);
    }
}
