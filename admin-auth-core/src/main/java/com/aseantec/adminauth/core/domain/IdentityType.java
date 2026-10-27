package com.aseantec.adminauth.core.domain;

/**
 * 登录标识类型：邮箱 / 手机号 / 系统派发的员工码。
 * <p>类型决定规范化规则（{@code IdentityNormalizer}）与 2FA 同源判断。</p>
 */
public enum IdentityType {
    EMAIL,
    PHONE,
    STAFF_CODE
}
