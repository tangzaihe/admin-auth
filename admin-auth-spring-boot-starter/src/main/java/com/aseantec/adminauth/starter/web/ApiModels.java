package com.aseantec.adminauth.starter.web;

import com.aseantec.adminauth.core.domain.AdminUser;
import com.aseantec.adminauth.core.domain.IdentityType;
import com.aseantec.adminauth.core.domain.MfaFactorType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.List;

/** REST 请求/响应模型（嵌套 record，便于集中维护契约）。 */
public final class ApiModels {

    private ApiModels() {
    }

    // ---------- 请求 ----------

    public record LoginRequest(@NotNull IdentityType identityType,
                               @NotBlank String identifier,
                               @NotBlank String password) {
    }

    public record PasswordChangeInitialRequest(@NotBlank String ticket,
                                               @NotBlank String oldPassword,
                                               @NotBlank String newPassword) {
    }

    public record MfaVerifyRequest(@NotBlank String ticket,
                                   @NotNull MfaFactorType factorType,
                                   @NotBlank String code) {
    }

    public record MfaRecoveryRequest(@NotBlank String ticket,
                                     @NotBlank String code) {
    }

    public record TotpSetupInitRequest(String ticket) {
    }

    public record TotpSetupConfirmRequest(String ticket,
                                          @NotBlank String code) {
    }

    public record OtpSendRequest(String ticket, MfaFactorType factorType) {
    }

    public record PasswordChangeRequest(@NotBlank String oldPassword,
                                        @NotBlank String newPassword) {
    }

    public record MfaDisableRequest(@NotBlank String password) {
    }

    public record MfaRequireRequest(int value) {
    }

    // ---------- 响应 ----------

    public record UserView(long id, String displayName, String role, boolean mustChangePassword, boolean mfaBound) {

        public static UserView of(AdminUser user) {
            return new UserView(user.id(), user.displayName(), user.role(), user.mustChangePassword(), user.mfaBound());
        }
    }

    public record LoginResponse(String next, String ticket, List<String> factors, UserView user) {
    }

    public record TotpSetupResponse(String otpauthUri, String qrSvg, String manualSecret) {
    }

    public record TotpConfirmResponse(List<String> recoveryCodes, String next, UserView user) {
    }

    public record MeResponse(long id, String displayName, String role, boolean mfaVerified,
                             boolean mfaBound, String version) {
    }

    public record FactorView(String type, String status, String confirmedAt, int priority) {
    }

    public record MfaSecurityResponse(int mfaState, List<FactorView> factors) {
    }

    // ---------- 管理台用户管理 ----------

    public record CreateUserRequest(String displayName,
                                    @NotBlank String role,
                                    @NotBlank String email,
                                    String staffCode,
                                    String password) {
    }

    public record UserStatusRequest(boolean enabled) {
    }

    public record IdentityView(String type, String mask, boolean primary, int status) {
    }

    public record AdminUserView(long id, String displayName, String role, String status,
                                boolean mustChangePassword, int mfaState, int mfaRequired,
                                String lastLoginAt, List<IdentityView> identities) {
    }

    public record AdminUserListResponse(List<AdminUserView> items, int page, int size, long total) {
    }

    public record CreateUserResponse(long userId, String emailMask, String staffCode, String temporaryPassword) {
    }

    public record ResetPasswordResponse(long userId, String temporaryPassword) {
    }
}
