package com.aseantec.adminauth.core.domain;

import java.time.Instant;

/** 一次性恢复码（{@code adm_recovery_code}），仅存 HMAC 哈希。 */
public record RecoveryCode(long id, long userId, String codeHash, Instant usedAt, Instant createdAt) {

    public boolean used() {
        return usedAt != null;
    }
}
