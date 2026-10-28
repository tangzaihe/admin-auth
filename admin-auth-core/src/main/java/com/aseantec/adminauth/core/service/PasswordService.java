package com.aseantec.adminauth.core.service;

import com.aseantec.adminauth.core.domain.AdminUser;
import com.aseantec.adminauth.core.domain.PasswordPolicyException;
import com.aseantec.adminauth.core.domain.PasswordPolicyReason;
import com.aseantec.adminauth.core.domain.UserStatus;
import com.aseantec.adminauth.core.port.AdminUserRepository;
import com.aseantec.adminauth.core.port.ClockProvider;
import com.aseantec.adminauth.core.port.PasswordVerifier;

/**
 * 密码修改与初始改密。
 *
 * <p><b>链路</b>：查账号 → 校验旧密码 → 策略校验（最小长度、不得与旧密码相同）
 * → BCrypt 重算 → {@code updatePassword}（同时 token_version+1、清 must_change_password）。</p>
 */
public class PasswordService {

    private final AdminUserRepository users;
    private final PasswordVerifier passwordVerifier;
    private final ClockProvider clock;
    private final int minLength;

    public PasswordService(AdminUserRepository users,
                           PasswordVerifier passwordVerifier,
                           ClockProvider clock,
                           int minLength) {
        this.users = users;
        this.passwordVerifier = passwordVerifier;
        this.clock = clock;
        this.minLength = Math.max(8, minLength);
    }

    /**
     * 修改密码。
     *
     * @param initialChange 是否为初始改密（口令流转由调用方保证）
     */
    public void changePassword(long userId, String oldPassword, String newPassword, boolean initialChange) {
        AdminUser user = users.findById(userId)
                .orElseThrow(() -> new PasswordPolicyException(PasswordPolicyReason.USER_NOT_FOUND));
        if (user.status() != UserStatus.ACTIVE) {
            throw new PasswordPolicyException(PasswordPolicyReason.USER_DISABLED);
        }
        if (oldPassword == null || !passwordVerifier.verify(oldPassword, user.passwordHash())) {
            throw new PasswordPolicyException(PasswordPolicyReason.OLD_PASSWORD_MISMATCH);
        }
        validate(newPassword, oldPassword);
        String hash = passwordVerifier.hash(newPassword);
        users.updatePassword(user.id(), hash, passwordVerifier.algorithm(), clock.now(), false);
    }

    protected void validate(String newPassword, String oldPassword) {
        if (newPassword == null || newPassword.length() < minLength) {
            throw new PasswordPolicyException(PasswordPolicyReason.TOO_SHORT, minLength);
        }
        if (newPassword.equals(oldPassword)) {
            throw new PasswordPolicyException(PasswordPolicyReason.SAME_AS_OLD);
        }
        if (newPassword.isBlank()) {
            throw new PasswordPolicyException(PasswordPolicyReason.BLANK);
        }
    }

    public int minLength() {
        return minLength;
    }
}
