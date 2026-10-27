package com.aseantec.adminauth.core.domain;

/** 第二因素校验失败；{@code locked} 为 true 时对外映射 423 MFA_LOCKED。 */
public class MfaVerificationException extends RuntimeException {

    private final boolean locked;

    public MfaVerificationException(String message) {
        this(message, false);
    }

    public MfaVerificationException(String message, boolean locked) {
        super(message);
        this.locked = locked;
    }

    public boolean locked() {
        return locked;
    }
}
