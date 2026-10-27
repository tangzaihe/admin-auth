package com.aseantec.adminauth.core.service;

import com.aseantec.adminauth.core.domain.IdentityType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IdentityNormalizerTest {

    private final DefaultIdentityNormalizer normalizer = new DefaultIdentityNormalizer();

    @Test
    @DisplayName("EMAIL：trim + 小写")
    void email() {
        assertThat(normalizer.normalize(IdentityType.EMAIL, "  Alice.Wang@Corp.Example  "))
                .isEqualTo("alice.wang@corp.example");
    }

    @Test
    @DisplayName("PHONE：去掉空格/短横线/括号/点，保留前导 +")
    void phone() {
        assertThat(normalizer.normalize(IdentityType.PHONE, "+86 138-0013-8000")).isEqualTo("+8613800138000");
        assertThat(normalizer.normalize(IdentityType.PHONE, "138 0013 8000")).isEqualTo("13800138000");
        assertThat(normalizer.normalize(IdentityType.PHONE, "(021) 5555.1234")).isEqualTo("02155551234");
    }

    @Test
    @DisplayName("STAFF_CODE：trim + 大写（用户输入 emp000123 与 EMP000123 等价）")
    void staffCode() {
        assertThat(normalizer.normalize(IdentityType.STAFF_CODE, "  emp000123 ")).isEqualTo("EMP000123");
    }

    @Test
    @DisplayName("空值与纯符号输入抛出参数异常，由登录层统一转 AUTH_FAILED")
    void invalid() {
        assertThatThrownBy(() -> normalizer.normalize(IdentityType.EMAIL, "   "))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> normalizer.normalize(IdentityType.PHONE, "---"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> normalizer.normalize(null, "x"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
