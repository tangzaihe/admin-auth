package com.aseantec.adminauth.core.domain;

/**
 * 第二因素失败原因。
 *
 * <p>与 {@link PasswordPolicyReason} 相同：只携带稳定消息键，不携带文案；翻译在 starter 层完成。</p>
 */
public enum MfaFailureReason {

    /** 待确认的绑定已失效（过期或被重置）。 */
    SETUP_EXPIRED("admin-auth.mfa.setup-expired"),

    /** 动态码不正确。 */
    CODE_INVALID("admin-auth.mfa.code-invalid"),

    /** 尚未绑定 TOTP。 */
    NOT_BOUND("admin-auth.mfa.not-bound"),

    /** 尝试次数过多，因素级锁定。 */
    TOO_MANY_ATTEMPTS("admin-auth.mfa.too-many-attempts"),

    /** 已绑定 TOTP，需先停用。 */
    ALREADY_BOUND("admin-auth.mfa.already-bound"),

    /** 绑定/校验时账号已不存在。 */
    ACCOUNT_NOT_FOUND("admin-auth.mfa.account-not-found");

    private final String messageKey;

    MfaFailureReason(String messageKey) {
        this.messageKey = messageKey;
    }

    public String messageKey() {
        return messageKey;
    }
}
