package com.aseantec.adminauth.core.domain;

/** 账号状态：1=正常 0=停用（软删除，保留审计链）。 */
public enum UserStatus {
    DISABLED(0),
    ACTIVE(1);

    private final int code;

    UserStatus(int code) {
        this.code = code;
    }

    public int code() {
        return code;
    }

    public static UserStatus fromCode(int code) {
        return code == ACTIVE.code ? ACTIVE : DISABLED;
    }
}
