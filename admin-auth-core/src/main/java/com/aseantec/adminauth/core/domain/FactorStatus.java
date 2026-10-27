package com.aseantec.adminauth.core.domain;

/** 第二因素状态：1=启用 0=停用 2=待确认（已生成 secret，用户尚未输码确认）。 */
public enum FactorStatus {
    DISABLED(0),
    ACTIVE(1),
    PENDING(2);

    private final int code;

    FactorStatus(int code) {
        this.code = code;
    }

    public int code() {
        return code;
    }

    public static FactorStatus fromCode(int code) {
        return switch (code) {
            case 1 -> ACTIVE;
            case 2 -> PENDING;
            default -> DISABLED;
        };
    }
}
