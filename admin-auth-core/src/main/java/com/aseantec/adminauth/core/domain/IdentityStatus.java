package com.aseantec.adminauth.core.domain;

/** 登录标识状态：1=启用 0=停用 2=保留（STAFF_CODE 停用后保留，永不复用）。 */
public enum IdentityStatus {
    DISABLED(0),
    ACTIVE(1),
    RESERVED(2);

    private final int code;

    IdentityStatus(int code) {
        this.code = code;
    }

    public int code() {
        return code;
    }

    public static IdentityStatus fromCode(int code) {
        return switch (code) {
            case 1 -> ACTIVE;
            case 2 -> RESERVED;
            default -> DISABLED;
        };
    }
}
