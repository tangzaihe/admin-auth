package com.aseantec.adminauth.core.crypto;

import com.aseantec.adminauth.core.domain.IdentityType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;

class HmacBlindIndexerTest {

    private static final byte[] KEY = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);

    @Test
    @DisplayName("HMAC-SHA256(indexKey, TYPE|normalized|v1) 结果稳定且为 32 字节")
    void stableVector() {
        HmacBlindIndexer indexer = new HmacBlindIndexer(KEY);
        byte[] index = indexer.index(IdentityType.EMAIL, "alice@corp.example");
        assertThat(index).hasSize(32);
        assertThat(HexFormat.of().formatHex(index))
                .isEqualTo("e484751438ff71be70721c2195ff26da60bd4c24374351b9aad739767541f0a2");
    }

    @Test
    @DisplayName("同值同类型稳定；不同类型/不同值/不同密钥产生不同索引（域名分隔防拼接歧义）")
    void distinctness() {
        HmacBlindIndexer indexer = new HmacBlindIndexer(KEY);
        byte[] email = indexer.index(IdentityType.EMAIL, "a@corp.example");
        assertThat(indexer.index(IdentityType.EMAIL, "a@corp.example")).isEqualTo(email);
        assertThat(indexer.index(IdentityType.STAFF_CODE, "a@corp.example")).isNotEqualTo(email);
        assertThat(indexer.index(IdentityType.EMAIL, "b@corp.example")).isNotEqualTo(email);
        assertThat(indexer.index(IdentityType.EMAIL, "a@corp.example|v1")).isNotEqualTo(email);
        assertThat(new HmacBlindIndexer("ffffffffffffffffffffffffffffffff".getBytes(StandardCharsets.UTF_8))
                .index(IdentityType.EMAIL, "a@corp.example")).isNotEqualTo(email);
    }
}
