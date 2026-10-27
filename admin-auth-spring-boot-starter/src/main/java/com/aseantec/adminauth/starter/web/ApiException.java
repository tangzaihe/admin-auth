package com.aseantec.adminauth.starter.web;

/** 业务异常：由 {@link ApiErrorHandler} 统一转换为 {@code {"code","message"}}。 */
public class ApiException extends RuntimeException {

    private final ApiErrorCode code;

    public ApiException(ApiErrorCode code) {
        this(code, code.defaultMessage());
    }

    public ApiException(ApiErrorCode code, String message) {
        super(message);
        this.code = code;
    }

    public ApiErrorCode code() {
        return code;
    }
}
