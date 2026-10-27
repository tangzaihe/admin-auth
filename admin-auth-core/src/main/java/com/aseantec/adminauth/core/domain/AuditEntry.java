package com.aseantec.adminauth.core.domain;

import java.time.Instant;

/**
 * 审计流水（{@code adm_audit_log}）：只增不改，敏感信息只落脱敏值。
 *
 * @param identityType 登录标识类型名（非登录类事件为空串）
 * @param factorType   第二因素类型名或 RECOVERY（非 2FA 事件为空串）
 * @param detail       扩展详情 JSON 字符串，必须脱敏
 */
public record AuditEntry(
        Long userId,
        Long actorUserId,
        String identityType,
        String factorType,
        String channelMask,
        AuditEvent event,
        AuditResult result,
        String ip,
        String userAgent,
        String detail,
        Instant createdAt) {

    public AuditEntry {
        identityType = identityType == null ? "" : identityType;
        factorType = factorType == null ? "" : factorType;
        channelMask = channelMask == null ? "" : channelMask;
        ip = ip == null ? "" : ip;
        userAgent = userAgent == null ? "" : userAgent;
    }
}
