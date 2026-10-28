package com.aseantec.adminauth.core.domain;

/**
 * 密码策略失败原因。
 *
 * <p>{@code messageKey()} 是<b>稳定消息键</b>，不是文案：core 层保持零 Spring 依赖，
 * 只负责携带键与参数，由 starter 的 {@code AdminAuthMessages} 按请求语言翻译。</p>
 */
public enum PasswordPolicyReason {

    /** 账号不存在。 */
    USER_NOT_FOUND("admin-auth.password.user-not-found"),

    /** 账号已停用。 */
    USER_DISABLED("admin-auth.password.user-disabled"),

    /** 原密码不正确（对外映射 {@code PASSWORD_MISMATCH}）。 */
    OLD_PASSWORD_MISMATCH("admin-auth.password.old-mismatch"),

    /** 新密码长度不足，参数为最小长度。 */
    TOO_SHORT("admin-auth.password.too-short"),

    /** 新密码与原密码相同。 */
    SAME_AS_OLD("admin-auth.password.same-as-old"),

    /** 新密码为空白字符。 */
    BLANK("admin-auth.password.blank");

    private final String messageKey;

    PasswordPolicyReason(String messageKey) {
        this.messageKey = messageKey;
    }

    public String messageKey() {
        return messageKey;
    }
}
