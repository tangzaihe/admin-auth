package com.aseantec.adminauth.core.domain;

/** 登录失败原因（对外统一映射：AUTH_FAILED 401 / LOCKED 423）。 */
public enum LoginFailure {
    AUTH_FAILED,
    LOCKED
}
