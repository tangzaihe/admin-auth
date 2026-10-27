package com.aseantec.adminauth.core.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class StaffCodeGeneratorTest {

    @Test
    @DisplayName("SEQUENTIAL：prefix + 零填充(startOffset + sequence)")
    void sequential() {
        StaffCodeGenerator generator = new StaffCodeGenerator("EMP", 6, 1000, StaffCodeGenerator.Strategy.SEQUENTIAL);
        assertThat(generator.generate(0)).isEqualTo("EMP001000");
        assertThat(generator.generate(123)).isEqualTo("EMP001123");
    }

    @Test
    @DisplayName("RANDOM：始终 prefix + digits 位数字")
    void random() {
        StaffCodeGenerator generator = new StaffCodeGenerator("emp", 6, 0, StaffCodeGenerator.Strategy.RANDOM);
        for (int i = 0; i < 20; i++) {
            assertThat(generator.generate(i)).matches("EMP\\d{6}");
        }
    }

    @Test
    @DisplayName("digits 下限为 4，超长序列截断尾部")
    void bounds() {
        StaffCodeGenerator generator = new StaffCodeGenerator("X", 2, 0, StaffCodeGenerator.Strategy.SEQUENTIAL);
        assertThat(generator.generate(7)).isEqualTo("X0007");
    }
}
