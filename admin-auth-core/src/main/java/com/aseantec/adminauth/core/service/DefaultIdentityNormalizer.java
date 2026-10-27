package com.aseantec.adminauth.core.service;

import com.aseantec.adminauth.core.domain.IdentityType;
import com.aseantec.adminauth.core.port.IdentityNormalizer;

import java.util.Locale;

/**
 * 默认规范化规则。
 * <ol>
 *   <li>EMAIL：trim + 小写；</li>
 *   <li>PHONE：去分隔符（空格/短横线/括号/点），保留前导 +；</li>
 *   <li>STAFF_CODE：trim + 大写。</li>
 * </ol>
 * 规范化结果同时用于盲索引计算，保证 "EMP000123" 与 " emp000123 " 命中同一行。
 */
public class DefaultIdentityNormalizer implements IdentityNormalizer {

    @Override
    public String normalize(IdentityType type, String raw) {
        if (type == null) {
            throw new IllegalArgumentException("标识类型不能为空");
        }
        if (raw == null) {
            throw new IllegalArgumentException("登录标识不能为空");
        }
        String value = raw.trim();
        if (value.isEmpty()) {
            throw new IllegalArgumentException("登录标识不能为空");
        }
        return switch (type) {
            case EMAIL -> value.toLowerCase(Locale.ROOT);
            case PHONE -> normalizePhone(value);
            case STAFF_CODE -> value.toUpperCase(Locale.ROOT);
        };
    }

    private String normalizePhone(String raw) {
        StringBuilder sb = new StringBuilder(raw.length());
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (Character.isDigit(c)) {
                sb.append(c);
            } else if (c == '+' && sb.isEmpty()) {
                sb.append('+');
            }
        }
        if (sb.isEmpty() || "+".contentEquals(sb)) {
            throw new IllegalArgumentException("手机号格式非法");
        }
        return sb.toString();
    }
}
