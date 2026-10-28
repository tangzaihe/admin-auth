package com.aseantec.adminauth.starter.web;

import com.aseantec.adminauth.core.domain.AdminUser;
import com.aseantec.adminauth.core.domain.AuditEntry;
import com.aseantec.adminauth.core.domain.AuditEvent;
import com.aseantec.adminauth.core.domain.AuditResult;
import com.aseantec.adminauth.core.port.AdminUserRepository;
import com.aseantec.adminauth.core.port.AuditRepository;
import com.aseantec.adminauth.core.port.AuditSink;
import com.aseantec.adminauth.core.port.ClockProvider;
import com.aseantec.adminauth.starter.AdminAuthProperties;
import com.aseantec.adminauth.starter.admin.AdminAuthTransactionalOperations;
import com.aseantec.adminauth.starter.admin.AdminAuthUserAdminService;
import com.aseantec.adminauth.starter.security.AdminSessionPrincipal;
import com.aseantec.adminauth.starter.security.AdminSessionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * 超级管理员接口（要求 SUPER_ADMIN + step-up，默认 5 分钟内完成过 2FA）。
 *
 * <p>覆盖：管理员账号创建/分页查询/启停/解锁/重置密码，以及 2FA 重置与策略覆盖、审计查询。</p>
 */
@RestController
@RequestMapping("${admin-auth.endpoint-prefix:/admin-auth}/api")
public class AdminApiController {

    private final AdminSessionService sessions;
    private final AdminUserRepository users;
    private final AdminAuthUserAdminService userAdminService;
    private final AdminAuthTransactionalOperations operations;
    private final AuditRepository auditRepository;
    private final AuditSink auditSink;
    private final AdminAuthProperties properties;
    private final ClockProvider clock;

    public AdminApiController(AdminSessionService sessions,
                              AdminUserRepository users,
                              AdminAuthUserAdminService userAdminService,
                              AdminAuthTransactionalOperations operations,
                              AuditRepository auditRepository,
                              AuditSink auditSink,
                              AdminAuthProperties properties,
                              ClockProvider clock) {
        this.sessions = sessions;
        this.users = users;
        this.userAdminService = userAdminService;
        this.operations = operations;
        this.auditRepository = auditRepository;
        this.auditSink = auditSink;
        this.properties = properties;
        this.clock = clock;
    }

    // ---------- 用户生命周期 ----------

    @GetMapping("/admin/users")
    public ApiModels.AdminUserListResponse listUsers(@RequestParam(defaultValue = "0") int page,
                                                     @RequestParam(defaultValue = "20") int size,
                                                     HttpServletRequest request) {
        requireAdmin(request);
        int safePage = Math.max(0, page);
        int safeSize = Math.max(1, Math.min(size, 100));
        List<ApiModels.AdminUserView> items = userAdminService.findPage(safePage, safeSize).stream()
                .map(this::toView)
                .toList();
        return new ApiModels.AdminUserListResponse(items, safePage, safeSize, userAdminService.countAll());
    }

    @PostMapping("/admin/users")
    public ApiModels.CreateUserResponse createUser(@Valid @RequestBody ApiModels.CreateUserRequest body,
                                                   HttpServletRequest request) {
        AdminSessionPrincipal actor = requireAdmin(request);
        String displayName = body.displayName() == null || body.displayName().isBlank()
                ? "管理员" : body.displayName().trim();
        AdminAuthUserAdminService.CreatedUser created = userAdminService.createUser(
                displayName, body.role().trim(), body.email(), body.staffCode(), body.password(), actor.userId());
        return new ApiModels.CreateUserResponse(created.userId(), created.emailMask(),
                created.staffCode(), created.temporaryPassword());
    }

    @PostMapping("/admin/users/{id}/status")
    public Map<String, Object> updateStatus(@PathVariable long id,
                                            @RequestBody ApiModels.UserStatusRequest body,
                                            HttpServletRequest request) {
        AdminSessionPrincipal actor = requireAdmin(request);
        if (id == actor.userId() && !body.enabled()) {
            throw new ApiException(ApiErrorCode.VALIDATION_FAILED, "admin-auth.error.cannot-disable-self");
        }
        AdminUser target = userAdminService.requireUser(id);
        if (!body.enabled() && target.superAdmin() && users.countByRole("SUPER_ADMIN") <= 1) {
            throw new ApiException(ApiErrorCode.VALIDATION_FAILED, "admin-auth.error.last-super-admin");
        }
        userAdminService.updateStatus(id, body.enabled(), actor.userId());
        if (!body.enabled()) {
            sessions.deleteAllSessionsOf(id);
        }
        return Map.of("ok", true, "userId", id, "enabled", body.enabled());
    }

    @PostMapping("/admin/users/{id}/unlock")
    public Map<String, Object> unlock(@PathVariable long id, HttpServletRequest request) {
        AdminSessionPrincipal actor = requireAdmin(request);
        userAdminService.unlock(id, actor.userId());
        return Map.of("ok", true, "userId", id);
    }

    @PostMapping("/admin/users/{id}/password/reset")
    public ApiModels.ResetPasswordResponse resetPassword(@PathVariable long id, HttpServletRequest request) {
        AdminSessionPrincipal actor = requireAdmin(request);
        String temporaryPassword = userAdminService.resetPassword(id, actor.userId());
        // 重置后该账号所有会话立刻失效，临时密码只返回这一次
        sessions.deleteAllSessionsOf(id);
        return new ApiModels.ResetPasswordResponse(id, temporaryPassword);
    }

    // ---------- 2FA 管理 ----------

    @PostMapping("/admin/users/{id}/mfa/reset")
    public Map<String, Object> resetUserMfa(@PathVariable long id, HttpServletRequest request) {
        requireAdmin(request);
        operations.adminResetMfa(id);
        // 管理员重置后，被操作账号全部会话立即失效
        sessions.deleteAllSessionsOf(id);
        return Map.of("ok", true, "userId", id);
    }

    @PostMapping("/admin/users/{id}/mfa/require")
    public Map<String, Object> requireUserMfa(@PathVariable long id,
                                              @Valid @RequestBody ApiModels.MfaRequireRequest body,
                                              HttpServletRequest request) {
        AdminSessionPrincipal actor = requireAdmin(request);
        if (body.value() != -1 && body.value() != 0 && body.value() != 1) {
            throw new ApiException(ApiErrorCode.VALIDATION_FAILED, "admin-auth.error.invalid-mfa-require-value");
        }
        users.findById(id).orElseThrow(() ->
                new ApiException(ApiErrorCode.VALIDATION_FAILED, "admin-auth.error.account-not-found"));
        users.updateMfaRequired(id, body.value());
        audit(actor, id, "{\"value\":" + body.value() + "}");
        sessions.deleteAllSessionsOf(id);
        return Map.of("ok", true, "userId", id, "mfaRequired", body.value());
    }

    @GetMapping("/admin/audit")
    public Map<String, Object> audit(@RequestParam(defaultValue = "50") int limit, HttpServletRequest request) {
        requireAdmin(request);
        List<AuditEntry> entries = auditRepository.findRecent(Math.max(1, Math.min(limit, 200)));
        return Map.of("items", entries);
    }

    // ---------- internals ----------

    private ApiModels.AdminUserView toView(AdminUser user) {
        List<ApiModels.IdentityView> identities = userAdminService.identitiesOf(user.id()).stream()
                .map(identity -> new ApiModels.IdentityView(identity.identityType().name(),
                        identity.valueMask(), identity.primary(), identity.status().code()))
                .toList();
        return new ApiModels.AdminUserView(user.id(), user.displayName(), user.role(), user.status().name(),
                user.mustChangePassword(), user.mfaState(), user.mfaRequired(),
                user.lastLoginAt() == null ? null : user.lastLoginAt().toString(), identities);
    }

    private AdminSessionPrincipal requireAdmin(HttpServletRequest request) {
        AdminSessionPrincipal principal = CurrentUser.require(request, sessions);
        if (!principal.superAdmin()) {
            throw new ApiException(ApiErrorCode.FORBIDDEN, "admin-auth.error.super-admin-required");
        }
        Instant verifiedAt = principal.mfaVerifiedAt();
        boolean stepUp = principal.mfaVerified() && verifiedAt != null
                && verifiedAt.plus(properties.getMfa().getStepUpTtl()).isAfter(clock.now());
        if (!stepUp) {
            throw new ApiException(ApiErrorCode.STEP_UP_REQUIRED, ApiErrorCode.STEP_UP_REQUIRED.messageKey());
        }
        return principal;
    }

    private void audit(AdminSessionPrincipal actor, long targetUserId, String detail) {
        try {
            auditSink.record(new AuditEntry(targetUserId, actor.userId(), "", "", "",
                    AuditEvent.MFA_REQUIRE_CHANGE, AuditResult.SUCCESS, "", "", detail, clock.now()));
        } catch (RuntimeException ignored) {
            // 审计失败不影响主流程
        }
    }
}
