package com.aseantec.adminauth.core.domain;

import java.time.Instant;

/**
 * 登录标识（{@code adm_identity}）。
 * <p>敏感字段三件套：{@code valueEnc}（AES-GCM 密文）、{@code valueHash}（HMAC 盲索引）、
 * {@code valueMask}（脱敏展示）。{@code active_hash} 为 MySQL 生成列，应用层永不写入。</p>
 */
public record AdminIdentity(
        long id,
        long userId,
        IdentityType identityType,
        byte[] valueEnc,
        int keyVersion,
        byte[] valueHash,
        String valueMask,
        Instant verifiedAt,
        Instant consentAt,
        String consentVersion,
        boolean primary,
        IdentityStatus status) {

    public boolean active() {
        return status == IdentityStatus.ACTIVE;
    }
}
