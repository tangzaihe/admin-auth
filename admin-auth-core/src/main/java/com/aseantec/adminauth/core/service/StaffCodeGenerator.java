package com.aseantec.adminauth.core.service;

import java.security.SecureRandom;
import java.util.Locale;

/**
 * STAFF_CODE 生成器。
 *
 * @param prefix      前缀（如 EMP）
 * @param digits      数字位数
 * @param startOffset 起始偏移（SEQUENTIAL 时 = startOffset + sequence）
 * @param strategy    SEQUENTIAL（可读、可推导）/ RANDOM（不可推导、冲突概率低）
 */
public class StaffCodeGenerator {

    public enum Strategy {
        SEQUENTIAL,
        RANDOM
    }

    private static final SecureRandom RANDOM = new SecureRandom();

    private final String prefix;
    private final int digits;
    private final long startOffset;
    private final Strategy strategy;

    public StaffCodeGenerator(String prefix, int digits, long startOffset, Strategy strategy) {
        this.prefix = prefix == null ? "" : prefix.trim().toUpperCase(Locale.ROOT);
        this.digits = Math.max(4, digits);
        this.startOffset = Math.max(0, startOffset);
        this.strategy = strategy == null ? Strategy.SEQUENTIAL : strategy;
    }

    public String generate(long sequence) {
        long base = strategy == Strategy.RANDOM
                ? RANDOM.nextLong(1, 1_000_000_000L)
                : startOffset + Math.max(0, sequence);
        String number = Long.toString(base);
        if (number.length() > digits) {
            number = number.substring(number.length() - digits);
        }
        return prefix + "0".repeat(digits - number.length()) + number;
    }

    public String prefix() {
        return prefix;
    }

    public int digits() {
        return digits;
    }
}
