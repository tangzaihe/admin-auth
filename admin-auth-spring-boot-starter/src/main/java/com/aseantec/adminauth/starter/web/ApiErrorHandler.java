package com.aseantec.adminauth.starter.web;

import com.aseantec.adminauth.core.domain.LoginFailedException;
import com.aseantec.adminauth.core.domain.LoginFailure;
import com.aseantec.adminauth.core.domain.MfaVerificationException;
import com.aseantec.adminauth.core.domain.PasswordPolicyException;
import com.aseantec.adminauth.core.domain.PasswordPolicyReason;
import com.aseantec.adminauth.starter.i18n.AdminAuthMessages;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * 统一错误响应：{@code {"code","message","messageKey"}}。
 *
 * <p>只作用于本组件控制器（basePackages 限定），避免污染宿主异常处理。</p>
 *
 * <p><b>i18n</b>：{@code code} 与 {@code messageKey} 稳定不变，{@code message} 按请求语言解析；
 * 语言来自 {@link Locale}（默认即 {@code Accept-Language}，宿主换 LocaleResolver 即可适配）。</p>
 */
@RestControllerAdvice(basePackages = "com.aseantec.adminauth.starter.web")
public class ApiErrorHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiErrorHandler.class);

    private static final String VALIDATION_FAILED_KEY = ApiErrorCode.VALIDATION_FAILED.messageKey();
    private static final String FIELD_KEY_PREFIX = "admin-auth.field.";
    private static final String VALIDATION_KEY_PREFIX = "admin-auth.validation.";
    private static final Object[] NO_ARGS = new Object[0];

    private final AdminAuthMessages messages;

    public ApiErrorHandler(AdminAuthMessages messages) {
        this.messages = messages;
    }

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<Map<String, Object>> handleApiException(ApiException e, Locale locale) {
        return body(e.code(), e.messageKey(), e.args(), locale);
    }

    @ExceptionHandler(LoginFailedException.class)
    public ResponseEntity<Map<String, Object>> handleLoginFailed(LoginFailedException e, Locale locale) {
        // 统一文案，不区分"账号不存在/密码错误/账号停用"
        ApiErrorCode code = e.failure() == LoginFailure.LOCKED ? ApiErrorCode.MFA_LOCKED : ApiErrorCode.AUTH_FAILED;
        return body(code, code.messageKey(), NO_ARGS, locale);
    }

    @ExceptionHandler(MfaVerificationException.class)
    public ResponseEntity<Map<String, Object>> handleMfa(MfaVerificationException e, Locale locale) {
        ApiErrorCode code = e.locked() ? ApiErrorCode.MFA_LOCKED : ApiErrorCode.AUTH_FAILED;
        return body(code, e.messageKey(), e.args(), locale);
    }

    @ExceptionHandler(PasswordPolicyException.class)
    public ResponseEntity<Map<String, Object>> handlePassword(PasswordPolicyException e, Locale locale) {
        boolean mismatch = e.reason() == PasswordPolicyReason.OLD_PASSWORD_MISMATCH
                // 旧构造器（宿主直接传文案）无 reason，只能按文案兜底判断
                || (e.reason() == null && e.getMessage() != null && e.getMessage().contains("原密码"));
        ApiErrorCode code = mismatch ? ApiErrorCode.PASSWORD_MISMATCH : ApiErrorCode.VALIDATION_FAILED;
        return body(code, e.messageKey(), e.args(), locale);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidation(MethodArgumentNotValidException e, Locale locale) {
        FieldError fieldError = e.getBindingResult().getFieldError();
        if (fieldError == null) {
            return body(ApiErrorCode.VALIDATION_FAILED, VALIDATION_FAILED_KEY, NO_ARGS, locale);
        }
        Object field = fieldLabel(fieldError.getField(), locale);
        String key = VALIDATION_KEY_PREFIX + constraint(fieldError.getCode());
        return body(ApiErrorCode.VALIDATION_FAILED, key, new Object[]{field}, locale);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> handleUnreadable(HttpMessageNotReadableException e, Locale locale) {
        return body(ApiErrorCode.VALIDATION_FAILED, "admin-auth.error.bad-request-body", NO_ARGS, locale);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalArgument(IllegalArgumentException e, Locale locale) {
        log.debug("admin-auth 请求参数非法: {}", e.getMessage());
        return body(ApiErrorCode.VALIDATION_FAILED, "admin-auth.error.invalid-input", NO_ARGS, locale);
    }

    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalState(IllegalStateException e, Locale locale) {
        log.warn("admin-auth 状态异常: {}", e.getMessage());
        return body(ApiErrorCode.VALIDATION_FAILED, "admin-auth.error.operation-failed", NO_ARGS, locale);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleUnexpected(Exception e, Locale locale) {
        log.error("admin-auth 未预期异常", e);
        return body(ApiErrorCode.INTERNAL_ERROR, ApiErrorCode.INTERNAL_ERROR.messageKey(), NO_ARGS, locale);
    }

    // ---------- internals ----------

    private Object fieldLabel(String field, Locale locale) {
        String key = FIELD_KEY_PREFIX + field;
        return messages.contains(locale, key) ? messages.message(locale, key) : field;
    }

    private String constraint(String code) {
        if (code == null) {
            return "invalid";
        }
        return switch (code) {
            case "NotBlank", "NotNull", "NotEmpty" -> "required";
            case "Size", "Length" -> "size";
            default -> "invalid";
        };
    }

    private ResponseEntity<Map<String, Object>> body(ApiErrorCode code, String messageKey, Object[] args, Locale locale) {
        Locale target = messages.resolve(locale);
        String message = messages.message(target, messageKey, args);
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("code", code.name());
        payload.put("message", message == null ? "" : message);
        if (messageKey != null && messages.contains(target, messageKey)) {
            payload.put("messageKey", messageKey);
        }
        HttpHeaders headers = new HttpHeaders();
        headers.setContentLanguage(target);
        headers.add(HttpHeaders.VARY, HttpHeaders.ACCEPT_LANGUAGE);
        return ResponseEntity.status(code.status()).headers(headers).body(payload);
    }
}
