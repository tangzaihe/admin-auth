package com.aseantec.adminauth.starter.web;

import com.aseantec.adminauth.core.domain.MfaFailureReason;
import com.aseantec.adminauth.core.domain.MfaVerificationException;
import com.aseantec.adminauth.core.domain.PasswordPolicyException;
import com.aseantec.adminauth.core.domain.PasswordPolicyReason;
import com.aseantec.adminauth.starter.i18n.AdminAuthMessages;
import com.aseantec.adminauth.starter.i18n.BundleAdminAuthMessages;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;

import java.lang.reflect.Method;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** 统一错误响应：code / messageKey 稳定，message 随语言变化。 */
class ApiErrorHandlerTest {

    private final AdminAuthMessages messages =
            new BundleAdminAuthMessages(true, "zh-CN", List.of("zh-CN", "en"));
    private final ApiErrorHandler handler = new ApiErrorHandler(messages);

    @Test
    @DisplayName("英文请求：错误码不变，message / Content-Language / messageKey 均正确")
    void localizesApiException() {
        ResponseEntity<Map<String, Object>> response =
                handler.handleApiException(new ApiException(ApiErrorCode.AUTH_FAILED), Locale.ENGLISH);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getHeaders().getContentLanguage()).isEqualTo(Locale.ENGLISH);
        assertThat(response.getBody())
                .containsEntry("code", "AUTH_FAILED")
                .containsEntry("messageKey", "admin-auth.error.auth-failed")
                .containsEntry("message", "Incorrect account or password");
    }

    @Test
    @DisplayName("因素锁定：423 + 具体原因键，而不是笼统文案")
    void localizesLockedMfa() {
        ResponseEntity<Map<String, Object>> response = handler.handleMfa(
                new MfaVerificationException(MfaFailureReason.TOO_MANY_ATTEMPTS, true),
                Locale.SIMPLIFIED_CHINESE);

        assertThat(response.getStatusCode().value()).isEqualTo(423);
        assertThat(response.getBody())
                .containsEntry("code", "MFA_LOCKED")
                .containsEntry("messageKey", "admin-auth.mfa.too-many-attempts");
        assertThat(response.getBody().get("message").toString()).contains("尝试次数过多");
    }

    @Test
    @DisplayName("原密码错误：code 仍为 PASSWORD_MISMATCH，文案由 reason 决定（不再靠字符串匹配）")
    void mapsOldPasswordMismatch() {
        ResponseEntity<Map<String, Object>> response = handler.handlePassword(
                new PasswordPolicyException(PasswordPolicyReason.OLD_PASSWORD_MISMATCH),
                Locale.SIMPLIFIED_CHINESE);

        assertThat(response.getBody())
                .containsEntry("code", "PASSWORD_MISMATCH")
                .containsEntry("message", "原密码不正确");
    }

    @Test
    @DisplayName("兼容宿主传入历史文案：未命中键时原样回显，且不伪造 messageKey")
    @SuppressWarnings("deprecation")
    void echoesLegacyLiteralMessage() {
        ResponseEntity<Map<String, Object>> response = handler.handlePassword(
                new PasswordPolicyException("原密码不正确"), Locale.ENGLISH);

        assertThat(response.getBody())
                .containsEntry("message", "原密码不正确")
                .doesNotContainKey("messageKey");
    }

    @Test
    @DisplayName("参数校验：字段名本地化为标签，文案带字段名")
    void buildsValidationMessageFromFieldLabel() throws Exception {
        Method method = Sample.class.getDeclaredMethod("handle", String.class);
        BeanPropertyBindingResult binding = new BeanPropertyBindingResult(new Object(), "loginRequest");
        binding.addError(new FieldError("loginRequest", "identifier", null, false,
                new String[]{"NotBlank"}, null, "must not be blank"));
        MethodArgumentNotValidException exception =
                new MethodArgumentNotValidException(new MethodParameter(method, 0), binding);

        ResponseEntity<Map<String, Object>> response = handler.handleValidation(exception, Locale.SIMPLIFIED_CHINESE);

        assertThat(response.getBody())
                .containsEntry("code", "VALIDATION_FAILED")
                .containsEntry("messageKey", "admin-auth.validation.required")
                .containsEntry("message", "账号不能为空");
    }

    @SuppressWarnings("unused")
    private static final class Sample {
        void handle(String body) {
        }
    }
}
