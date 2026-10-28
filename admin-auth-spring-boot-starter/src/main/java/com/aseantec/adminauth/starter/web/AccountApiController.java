package com.aseantec.adminauth.starter.web;

import com.aseantec.adminauth.core.domain.AdminUser;
import com.aseantec.adminauth.core.domain.AuditEntry;
import com.aseantec.adminauth.core.domain.AuditEvent;
import com.aseantec.adminauth.core.domain.AuditResult;
import com.aseantec.adminauth.core.domain.FactorStatus;
import com.aseantec.adminauth.core.domain.MfaFactor;
import com.aseantec.adminauth.core.port.AdminUserRepository;
import com.aseantec.adminauth.core.port.AuditSink;
import com.aseantec.adminauth.core.port.ClockProvider;
import com.aseantec.adminauth.core.port.MfaPolicy;
import com.aseantec.adminauth.core.port.PasswordVerifier;
import com.aseantec.adminauth.core.service.MfaService;
import com.aseantec.adminauth.starter.AdminAuthVersion;
import com.aseantec.adminauth.starter.admin.AdminAuthTransactionalOperations;
import com.aseantec.adminauth.starter.security.AdminSessionPrincipal;
import com.aseantec.adminauth.starter.security.AdminSessionService;
import com.aseantec.adminauth.starter.spi.AdminUserProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/** 已登录接口：当前用户 / 2FA 状态 / 停用 2FA / 改密 / 注销。 */
@RestController
@RequestMapping("${admin-auth.endpoint-prefix:/admin-auth}/api")
public class AccountApiController {

    private final AdminSessionService sessions;
    private final AdminUserProvider userProvider;
    private final AdminUserRepository users;
    private final MfaService mfaService;
    private final AdminAuthTransactionalOperations operations;
    private final PasswordVerifier passwordVerifier;
    private final MfaPolicy mfaPolicy;
    private final AuditSink audit;
    private final ClockProvider clock;

    public AccountApiController(AdminSessionService sessions,
                                AdminUserProvider userProvider,
                                AdminUserRepository users,
                                MfaService mfaService,
                                AdminAuthTransactionalOperations operations,
                                PasswordVerifier passwordVerifier,
                                MfaPolicy mfaPolicy,
                                AuditSink audit,
                                ClockProvider clock) {
        this.sessions = sessions;
        this.userProvider = userProvider;
        this.users = users;
        this.mfaService = mfaService;
        this.operations = operations;
        this.passwordVerifier = passwordVerifier;
        this.mfaPolicy = mfaPolicy;
        this.audit = audit;
        this.clock = clock;
    }

    @GetMapping("/me")
    public ApiModels.MeResponse me(HttpServletRequest request) {
        AdminSessionPrincipal principal = CurrentUser.require(request, sessions);
        boolean mfaBound = userProvider.findById(principal.userId())
                .map(AdminUser::mfaBound)
                .orElse(false);
        return new ApiModels.MeResponse(principal.userId(), principal.displayName(), principal.role(),
                principal.mfaVerified(), mfaBound, AdminAuthVersion.VERSION);
    }

    @GetMapping("/security/mfa")
    public ApiModels.MfaSecurityResponse mfaSecurity(HttpServletRequest request) {
        AdminSessionPrincipal principal = CurrentUser.require(request, sessions);
        List<MfaFactor> factors = mfaService.listFactors(principal.userId());
        List<ApiModels.FactorView> views = factors.stream()
                .map(factor -> new ApiModels.FactorView(
                        factor.factorType().name(),
                        statusName(factor.status()),
                        factor.confirmedAt() == null ? null : factor.confirmedAt().toString(),
                        factor.priority()))
                .toList();
        int state = userProvider.findById(principal.userId()).map(AdminUser::mfaState).orElse(0);
        return new ApiModels.MfaSecurityResponse(state, views);
    }

    @PostMapping("/security/mfa/disable")
    public Map<String, Object> disableMfa(@Valid @RequestBody ApiModels.MfaDisableRequest body,
                                          HttpServletRequest request) {
        AdminSessionPrincipal principal = CurrentUser.require(request, sessions);
        AdminUser user = users.findById(principal.userId())
                .orElseThrow(() -> new ApiException(ApiErrorCode.AUTH_FAILED));
        if (!passwordVerifier.verify(body.password(), user.passwordHash())) {
            throw new ApiException(ApiErrorCode.PASSWORD_MISMATCH);
        }
        // 强制策略（REQUIRED_ALL / 命中角色的 REQUIRED_BY_ROLE）下不允许自行关闭 2FA
        if (mfaPolicy.mandatory(user)) {
            throw new ApiException(ApiErrorCode.MFA_REQUIRED_BY_POLICY, "admin-auth.error.mfa-cannot-disable");
        }
        operations.disableMfa(principal.userId());
        return Map.of("ok", true);    }

    @PostMapping("/password/change")
    public Map<String, Object> changePassword(@Valid @RequestBody ApiModels.PasswordChangeRequest body,
                                              HttpServletRequest request) {
        AdminSessionPrincipal principal = CurrentUser.require(request, sessions);
        operations.changePassword(principal.userId(), body.oldPassword(), body.newPassword(), false);
        audit(principal.userId(), AuditEvent.PASSWORD_CHANGE);
        // 改密后按 principal name 删除该用户全部会话，本人需重新登录
        sessions.deleteAllSessionsOf(principal.userId());
        sessions.invalidate(request);
        return Map.of("ok", true, "next", "RELOGIN");
    }

    @PostMapping("/logout")
    public Map<String, Object> logout(HttpServletRequest request) {
        AdminSessionPrincipal principal = sessions.current(request);
        if (principal != null) {
            audit(principal.userId(), AuditEvent.LOGOUT);
        }
        sessions.invalidate(request);
        return Map.of("ok", true);
    }

    private void audit(long userId, AuditEvent event) {
        try {
            audit.record(new AuditEntry(userId, userId, "", "", "", event, AuditResult.SUCCESS,
                    "", "", null, clock.now()));
        } catch (RuntimeException ignored) {
            // 审计失败不影响主流程
        }
    }

    private String statusName(FactorStatus status) {
        return switch (status) {
            case ACTIVE -> "ACTIVE";
            case PENDING -> "PENDING";
            case DISABLED -> "DISABLED";
        };
    }
}
