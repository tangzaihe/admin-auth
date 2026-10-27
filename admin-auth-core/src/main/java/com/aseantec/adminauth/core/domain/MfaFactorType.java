package com.aseantec.adminauth.core.domain;

/**
 * 第二因素类型。v1 只实现 {@link #TOTP}；{@link #EMAIL_OTP}/{@link #SMS_OTP} 仅保留 SPI 与表结构。
 */
public enum MfaFactorType {
    TOTP,
    EMAIL_OTP,
    SMS_OTP;

    public boolean isOtp() {
        return this == EMAIL_OTP || this == SMS_OTP;
    }

    /** OTP 通道是否与登录标识同源（邮箱验证码 vs 邮箱登录）。 */
    public boolean sameChannelAs(IdentityType identityType) {
        return switch (this) {
            case EMAIL_OTP -> identityType == IdentityType.EMAIL;
            case SMS_OTP -> identityType == IdentityType.PHONE;
            case TOTP -> false;
        };
    }
}
