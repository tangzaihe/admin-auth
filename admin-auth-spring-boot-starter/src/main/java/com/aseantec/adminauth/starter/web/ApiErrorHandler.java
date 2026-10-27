package com.aseantec.adminauth.starter.web;

import com.aseantec.adminauth.core.domain.LoginFailedException;
import com.aseantec.adminauth.core.domain.LoginFailure;
import com.aseantec.adminauth.core.domain.MfaVerificationException;
import com.aseantec.adminauth.core.domain.PasswordPolicyException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 统一错误响应：{@code {"code","message"}}。
 * <p>只作用于本组件控制器（basePackages 限定），避免污染宿主异常处理。</p>
 */
@RestControllerAdvice(basePackages = "com.aseantec.adminauth.starter.web")
public class ApiErrorHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiErrorHandler.class);

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<Map<String, Object>> handleApiException(ApiException e) {
        return body(e.code().status(), e.code().name(), e.getMessage());
    }

    @ExceptionHandler(LoginFailedException.class)
    public ResponseEntity<Map<String, Object>> handleLoginFailed(LoginFailedException e) {
        if (e.failure() == LoginFailure.LOCKED) {
            return body(ApiErrorCode.MFA_LOCKED.status(), ApiErrorCode.MFA_LOCKED.name(),
                    ApiErrorCode.MFA_LOCKED.defaultMessage());
        }
        // 统一文案，不区分"账号不存在/密码错误/账号停用"
        return body(ApiErrorCode.AUTH_FAILED.status(), ApiErrorCode.AUTH_FAILED.name(),
                ApiErrorCode.AUTH_FAILED.defaultMessage());
    }

    @ExceptionHandler(MfaVerificationException.class)
    public ResponseEntity<Map<String, Object>> handleMfa(MfaVerificationException e) {
        ApiErrorCode code = e.locked() ? ApiErrorCode.MFA_LOCKED : ApiErrorCode.AUTH_FAILED;
        return body(code.status(), code.name(), e.getMessage());
    }

    @ExceptionHandler(PasswordPolicyException.class)
    public ResponseEntity<Map<String, Object>> handlePassword(PasswordPolicyException e) {
        boolean mismatch = e.getMessage() != null && e.getMessage().contains("原密码");
        ApiErrorCode code = mismatch ? ApiErrorCode.PASSWORD_MISMATCH : ApiErrorCode.VALIDATION_FAILED;
        return body(code.status(), code.name(), e.getMessage());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidation(MethodArgumentNotValidException e) {
        FieldError fieldError = e.getBindingResult().getFieldError();
        String message = fieldError == null
                ? ApiErrorCode.VALIDATION_FAILED.defaultMessage()
                : fieldError.getField() + " " + fieldError.getDefaultMessage();
        return body(ApiErrorCode.VALIDATION_FAILED.status(), ApiErrorCode.VALIDATION_FAILED.name(), message);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> handleUnreadable(HttpMessageNotReadableException e) {
        return body(ApiErrorCode.VALIDATION_FAILED.status(), ApiErrorCode.VALIDATION_FAILED.name(),
                "请求体格式不正确");
    }

    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalState(IllegalStateException e) {
        return body(ApiErrorCode.VALIDATION_FAILED.status(), ApiErrorCode.VALIDATION_FAILED.name(), e.getMessage());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleUnexpected(Exception e) {
        log.error("admin-auth 未预期异常", e);
        return body(ApiErrorCode.INTERNAL_ERROR.status(), ApiErrorCode.INTERNAL_ERROR.name(),
                ApiErrorCode.INTERNAL_ERROR.defaultMessage());
    }

    private ResponseEntity<Map<String, Object>> body(HttpStatus status, String code, String message) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("code", code);
        payload.put("message", message == null ? "" : message);
        return ResponseEntity.status(status).body(payload);
    }
}
