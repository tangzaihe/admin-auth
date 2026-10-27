package com.aseantec.adminauth.core.domain;

/** 密码策略校验失败（长度不足、与原密码相同等），对外映射 400 VALIDATION_FAILED / PASSWORD_MISMATCH。 */
public class PasswordPolicyException extends RuntimeException {

    public PasswordPolicyException(String message) {
        super(message);
    }
}
