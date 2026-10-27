package com.aseantec.adminauth.core.domain;

import java.time.Instant;

/** 登录失败计数（{@code adm_login_attempt}）：标识+IP 唯一行，命中账号后回填 user_id。 */
public record LoginAttempt(
        long id,
        Long userId,
        byte[] identityHash,
        String ip,
        int failCount,
        Instant lockedUntil,
        Instant updatedAt) {

    public boolean lockedAt(Instant now) {
        return lockedUntil != null && lockedUntil.isAfter(now);
    }
}
