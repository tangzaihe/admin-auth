package com.aseantec.adminauth.core.util;

import com.aseantec.adminauth.core.domain.IdentityType;

/** 脱敏展示：EMAIL / PHONE / STAFF_CODE。 */
public final class Masking {

    private Masking() {
    }

    public static String of(IdentityType type, String value) {
        return switch (type) {
            case EMAIL -> email(value);
            case PHONE -> phone(value);
            case STAFF_CODE -> staffCode(value);
        };
    }

    public static String email(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        int at = value.indexOf('@');
        if (at <= 0) {
            return generic(value);
        }
        return value.charAt(0) + "***" + value.substring(at);
    }

    public static String phone(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        String digits = value.replaceAll("[^0-9]", "");
        // 带国家码（如 +86）时按国内号码脱敏，避免把 "86" 当成号段
        if (digits.length() > 11 && digits.startsWith("86")) {
            digits = digits.substring(2);
        }
        if (digits.length() < 7) {
            return generic(digits);
        }
        return digits.substring(0, 3) + "****" + digits.substring(digits.length() - 4);
    }

    public static String staffCode(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        if (value.length() <= 4) {
            return value.charAt(0) + "***";
        }
        return value.substring(0, 2) + "****" + value.substring(value.length() - 2);
    }

    private static String generic(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        return value.charAt(0) + "***";
    }
}
