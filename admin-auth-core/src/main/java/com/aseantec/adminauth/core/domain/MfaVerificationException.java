package com.aseantec.adminauth.core.domain;

/**
 * 第二因素校验失败；{@code locked} 为 true 时对外映射 423 MFA_LOCKED。
 *
 * <p><b>i18n</b>：异常只携带 {@link MfaFailureReason} 与参数，不携带最终文案；
 * {@link #getMessage()} 返回稳定消息键，供 starter 层翻译与日志排查。</p>
 */
public class MfaVerificationException extends RuntimeException {

    private final MfaFailureReason reason;
    private final boolean locked;
    private final Object[] args;

    public MfaVerificationException(MfaFailureReason reason) {
        this(reason, false);
    }

    public MfaVerificationException(MfaFailureReason reason, boolean locked, Object... args) {
        super(reason == null ? "admin-auth.mfa.failed" : reason.messageKey());
        this.reason = reason;
        this.locked = locked;
        this.args = args == null ? new Object[0] : args;
    }

    /**
     * @deprecated 直接传文案的旧构造器，仅为兼容宿主保留；新代码请传 {@link MfaFailureReason}。
     */
    @Deprecated
    public MfaVerificationException(String message) {
        this(message, false);
    }

    /**
     * @deprecated 直接传文案的旧构造器，仅为兼容宿主保留；新代码请传 {@link MfaFailureReason}。
     */
    @Deprecated
    public MfaVerificationException(String message, boolean locked) {
        super(message);
        this.reason = null;
        this.locked = locked;
        this.args = new Object[0];
    }

    /** 失败原因；旧构造器创建的异常为 null。 */
    public MfaFailureReason reason() {
        return reason;
    }

    public boolean locked() {
        return locked;
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
