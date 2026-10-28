package com.aseantec.adminauth.core.domain;

/**
 * 密码策略校验失败（长度不足、与原密码相同等），对外映射 400 VALIDATION_FAILED / PASSWORD_MISMATCH。
 *
 * <p><b>i18n</b>：异常只携带 {@link PasswordPolicyReason} 与参数，不携带最终文案；
 * {@link #getMessage()} 返回稳定消息键，供 starter 层翻译与日志排查。</p>
 */
public class PasswordPolicyException extends RuntimeException {

    private final PasswordPolicyReason reason;
    private final Object[] args;

    public PasswordPolicyException(PasswordPolicyReason reason, Object... args) {
        super(reason == null ? "admin-auth.password.failed" : reason.messageKey());
        this.reason = reason;
        this.args = args == null ? new Object[0] : args;
    }

    /**
     * @deprecated 直接传文案的旧构造器，仅为兼容宿主保留；新代码请传 {@link PasswordPolicyReason}。
     */
    @Deprecated
    public PasswordPolicyException(String message) {
        super(message);
        this.reason = null;
        this.args = new Object[0];
    }

    /** 失败原因；旧构造器创建的异常为 null。 */
    public PasswordPolicyReason reason() {
        return reason;
    }

    /** 消息参数（对应 bundle 中的 {0}/{1}）。 */
    public Object[] args() {
        return args;
    }

    /** 稳定消息键；旧构造器创建时返回原始文案。 */
    public String messageKey() {
        return getMessage();
    }
}
