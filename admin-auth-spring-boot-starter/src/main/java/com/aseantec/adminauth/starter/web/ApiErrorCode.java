package com.aseantec.adminauth.starter.web;

import org.springframework.http.HttpStatus;

import java.util.Locale;

/**
 * 统一错误码（对应第 6 段错误码表）。
 *
 * <p><b>i18n</b>：枚举只保留 HTTP 状态，文案由消息键
 * {@code admin-auth.error.<code>} 决定（见 {@code i18n/admin-auth-messages*.properties}）。
 * {@code code} 是稳定契约，不随语言变化；{@code message} 才是本地化文本。</p>
 */
public enum ApiErrorCode {
    AUTH_FAILED(HttpStatus.UNAUTHORIZED),
    TICKET_EXPIRED(HttpStatus.UNAUTHORIZED),
    MFA_REQUIRED(HttpStatus.UNAUTHORIZED),
    MFA_LOCKED(HttpStatus.LOCKED),
    CHANNEL_FORBIDDEN(HttpStatus.BAD_REQUEST),
    MFA_REQUIRED_BY_POLICY(HttpStatus.FORBIDDEN),
    STEP_UP_REQUIRED(HttpStatus.FORBIDDEN),
    FORBIDDEN(HttpStatus.FORBIDDEN),
    NOT_IMPLEMENTED(HttpStatus.NOT_IMPLEMENTED),
    VALIDATION_FAILED(HttpStatus.BAD_REQUEST),
    PASSWORD_MISMATCH(HttpStatus.BAD_REQUEST),
    INTERNAL_ERROR(HttpStatus.INTERNAL_SERVER_ERROR);

    private final HttpStatus status;

    ApiErrorCode(HttpStatus status) {
        this.status = status;
    }

    public HttpStatus status() {
        return status;
    }

    /** 稳定消息键：{@code admin-auth.error.<kebab-case>}。 */
    public String messageKey() {
        return "admin-auth.error." + name().toLowerCase(Locale.ROOT).replace('_', '-');
    }
}
