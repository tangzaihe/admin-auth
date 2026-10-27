package com.aseantec.adminauth.core.domain;

/** 审计事件类型，与 {@code adm_audit_log.event} 对应。 */
public enum AuditEvent {
    LOGIN_PASSWORD_OK,
    LOGIN_FAIL,
    MFA_BIND,
    MFA_VERIFY_OK,
    MFA_VERIFY_FAIL,
    MFA_RESET,
    MFA_DISABLE,
    MFA_REQUIRE_CHANGE,
    PASSWORD_CHANGE,
    PASSWORD_RESET,
    USER_CREATE,
    USER_ENABLE,
    USER_DISABLE,
    USER_UNLOCK,
    LOGOUT,
    LOCKED,
    BREAK_GLASS,
    SESSION_INVALIDATED,
    BOOTSTRAP
}
