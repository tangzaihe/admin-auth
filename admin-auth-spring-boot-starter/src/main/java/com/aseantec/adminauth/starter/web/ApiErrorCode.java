package com.aseantec.adminauth.starter.web;

import org.springframework.http.HttpStatus;

/** 统一错误码（对应第 6 段错误码表）。 */
public enum ApiErrorCode {
    AUTH_FAILED(HttpStatus.UNAUTHORIZED, "账号或密码错误"),
    TICKET_EXPIRED(HttpStatus.UNAUTHORIZED, "登录会话已过期，请重新登录"),
    MFA_REQUIRED(HttpStatus.UNAUTHORIZED, "需要完成第二因素验证"),
    MFA_LOCKED(HttpStatus.LOCKED, "尝试次数过多，请稍后再试"),
    CHANNEL_FORBIDDEN(HttpStatus.BAD_REQUEST, "该验证通道与登录标识同源，已禁用"),
    MFA_REQUIRED_BY_POLICY(HttpStatus.FORBIDDEN, "当前账号被要求启用 2FA"),
    STEP_UP_REQUIRED(HttpStatus.FORBIDDEN, "需要重新完成二次验证"),
    FORBIDDEN(HttpStatus.FORBIDDEN, "无权访问"),
    NOT_IMPLEMENTED(HttpStatus.NOT_IMPLEMENTED, "该能力尚未实现"),
    VALIDATION_FAILED(HttpStatus.BAD_REQUEST, "参数校验失败"),
    PASSWORD_MISMATCH(HttpStatus.BAD_REQUEST, "原密码不正确"),
    INTERNAL_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "服务器内部错误");

    private final HttpStatus status;
    private final String defaultMessage;

    ApiErrorCode(HttpStatus status, String defaultMessage) {
        this.status = status;
        this.defaultMessage = defaultMessage;
    }

    public HttpStatus status() {
        return status;
    }

    public String defaultMessage() {
        return defaultMessage;
    }
}
