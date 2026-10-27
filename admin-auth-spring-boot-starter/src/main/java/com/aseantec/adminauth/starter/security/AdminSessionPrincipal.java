package com.aseantec.adminauth.starter.security;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;

/**
 * 会话中的登录主体（必须 Serializable，第 8 段坑 ⑦）。
 * <p>存放在 session 的 {@code ADM_PRINCIPAL} 属性；{@code userId} 同时写入
 * {@code PRINCIPAL_NAME_INDEX_NAME}，用于按人删除会话。</p>
 */
public record AdminSessionPrincipal(
        long userId,
        String displayName,
        String role,
        boolean mfaVerified,
        Instant authenticatedAt,
        Instant absoluteExpireAt,
        Instant mfaVerifiedAt) implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    public boolean superAdmin() {
        return "SUPER_ADMIN".equalsIgnoreCase(role);
    }
}
