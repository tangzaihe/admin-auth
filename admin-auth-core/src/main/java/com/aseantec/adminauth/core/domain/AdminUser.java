package com.aseantec.adminauth.core.domain;

import java.time.Instant;

/**
 * 账号主体（{@code adm_user}）。
 *
 * @param id                 主键
 * @param displayName        显示名
 * @param role               粗粒度角色：SUPER_ADMIN / ADMIN / VIEWER
 * @param status             账号状态
 * @param passwordHash       密码哈希（BCrypt）
 * @param passwordAlgo       密码算法标识
 * @param mustChangePassword 是否强制改密
 * @param mfaState           2FA 汇总状态：0 未绑定 / 1 已绑定 / 2 重置中
 * @param mfaRequired        用户级覆盖：-1 继承 / 0 关闭 / 1 开启
 * @param tokenVersion       令牌版本（改密、停用、重置时 +1）
 * @param pwdUpdatedAt       最近改密时间
 * @param lastLoginAt        最近成功登录时间
 * @param createdAt          创建时间
 * @param updatedAt          更新时间
 */
public record AdminUser(
        long id,
        String displayName,
        String role,
        UserStatus status,
        String passwordHash,
        String passwordAlgo,
        boolean mustChangePassword,
        int mfaState,
        int mfaRequired,
        int tokenVersion,
        Instant pwdUpdatedAt,
        Instant lastLoginAt,
        Instant createdAt,
        Instant updatedAt) {

    public boolean active() {
        return status == UserStatus.ACTIVE;
    }

    public boolean mfaBound() {
        return mfaState == 1;
    }

    public boolean superAdmin() {
        return "SUPER_ADMIN".equalsIgnoreCase(role);
    }

    public boolean inheritMfaPolicy() {
        return mfaRequired == -1;
    }
}
