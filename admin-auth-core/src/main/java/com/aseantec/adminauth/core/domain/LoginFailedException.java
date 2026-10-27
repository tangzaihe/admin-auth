package com.aseantec.adminauth.core.domain;

/** 登录失败异常：账号不存在/密码错误统一 {@link LoginFailure#AUTH_FAILED}，锁定为 {@link LoginFailure#LOCKED}。 */
public class LoginFailedException extends RuntimeException {

    private final LoginFailure failure;

    public LoginFailedException(LoginFailure failure) {
        super(failure.name());
        this.failure = failure;
    }

    public LoginFailure failure() {
        return failure;
    }
}
