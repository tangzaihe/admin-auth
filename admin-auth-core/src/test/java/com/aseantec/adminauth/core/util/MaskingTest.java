package com.aseantec.adminauth.core.util;

import com.aseantec.adminauth.core.domain.IdentityType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class MaskingTest {

    @Test
    @DisplayName("EMAIL 保留首字符与域名：a***@corp.com")
    void email() {
        assertThat(Masking.email("alice@corp.example")).isEqualTo("a***@corp.example");
        assertThat(Masking.email("a@corp.example")).isEqualTo("a***@corp.example");
    }

    @Test
    @DisplayName("PHONE 保留前 3 后 4：138****1234")
    void phone() {
        assertThat(Masking.phone("+8613800138000")).isEqualTo("138****8000");
        assertThat(Masking.phone("13800138000")).isEqualTo("138****8000");
    }

    @Test
    @DisplayName("STAFF_CODE 保留前 2 后 2：EM****23")
    void staffCode() {
        assertThat(Masking.staffCode("EMP000123")).isEqualTo("EM****23");
    }

    @Test
    @DisplayName("按类型分发；空值返回空串")
    void dispatch() {
        assertThat(Masking.of(IdentityType.EMAIL, "bob@corp.example")).isEqualTo("b***@corp.example");
        assertThat(Masking.of(IdentityType.PHONE, "13800138000")).isEqualTo("138****8000");
        assertThat(Masking.of(IdentityType.STAFF_CODE, "EMP000123")).isEqualTo("EM****23");
        assertThat(Masking.of(IdentityType.EMAIL, "")).isEmpty();
    }
}
