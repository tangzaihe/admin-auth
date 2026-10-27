package com.aseantec.adminauth.core.domain;

import java.time.Instant;

/**
 * 第二因素（{@code adm_mfa_factor}）。
 *
 * @param identityId   OTP 类型的发送通道（指向 adm_identity.id）；TOTP 填 0 哨兵，避免 NULL 唯一键失效
 * @param secretEnc    TOTP 共享密钥密文；OTP 类型为 null
 * @param lastUsedStep 已成功使用的最大时间步，用于防重放
 */
public record MfaFactor(
        long id,
        long userId,
        MfaFactorType factorType,
        long identityId,
        byte[] secretEnc,
        int keyVersion,
        int digits,
        int period,
        long lastUsedStep,
        String payload,
        int priority,
        Instant confirmedAt,
        int failCount,
        Instant lockedUntil,
        FactorStatus status) {

    public boolean active() {
        return status == FactorStatus.ACTIVE;
    }

    public boolean pending() {
        return status == FactorStatus.PENDING;
    }

    public boolean lockedAt(Instant now) {
        return lockedUntil != null && lockedUntil.isAfter(now);
    }
}
