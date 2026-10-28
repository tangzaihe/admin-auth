package com.aseantec.adminauth.starter.web;

import com.aseantec.adminauth.core.domain.AdminUser;
import com.aseantec.adminauth.core.domain.LoginStep;
import com.aseantec.adminauth.core.domain.MfaFactorType;
import com.aseantec.adminauth.core.domain.MfaVerificationException;
import com.aseantec.adminauth.core.domain.TotpSetupResult;
import com.aseantec.adminauth.core.service.MfaService;
import com.aseantec.adminauth.core.service.LockoutService;
import com.aseantec.adminauth.starter.AdminAuthProperties;
import com.aseantec.adminauth.starter.admin.AdminAuthTransactionalOperations;
import com.aseantec.adminauth.starter.security.AdminSessionPrincipal;
import com.aseantec.adminauth.starter.security.AdminSessionService;
import com.aseantec.adminauth.starter.spi.AdminUserProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 第二因素接口：TOTP 校验 / 恢复码 / 绑定初始化与确认 / OTP 发送占位。
 *
 * <p>绑定与确认既支持 pre-auth ticket（登录流程），也支持已登录会话（个人中心）。</p>
 */
@RestController
@RequestMapping("${admin-auth.endpoint-prefix:/admin-auth}/api")
public class MfaApiController {

    private final MfaService mfaService;
    private final AdminAuthTransactionalOperations operations;
    private final PreAuthTicketService tickets;
    private final AdminSessionService sessions;
    private final AdminUserProvider userProvider;
    private final QrCodeService qrCodeService;
    private final AdminAuthProperties properties;
    private final LockoutService lockout;

    public MfaApiController(MfaService mfaService,
                            AdminAuthTransactionalOperations operations,
                            PreAuthTicketService tickets,
                            AdminSessionService sessions,
                            AdminUserProvider userProvider,
                            QrCodeService qrCodeService,
                            AdminAuthProperties properties,
                            LockoutService lockout) {
        this.mfaService = mfaService;
        this.operations = operations;
        this.tickets = tickets;
        this.sessions = sessions;
        this.userProvider = userProvider;
        this.qrCodeService = qrCodeService;
        this.properties = properties;
        this.lockout = lockout;
    }

    @PostMapping("/mfa/verify")
    public ApiModels.LoginResponse verify(@Valid @RequestBody ApiModels.MfaVerifyRequest body,
                                          HttpServletRequest request) {
        HttpSession session = request.getSession(true);
        PreAuthTicket ticket = tickets.require(session, body.ticket(), LoginStep.SELECT_FACTOR);
        if (body.factorType() != MfaFactorType.TOTP) {
            if (properties.getMfa().isForbidSameChannel() && body.factorType().sameChannelAs(ticket.identityType())) {
                throw new ApiException(ApiErrorCode.CHANNEL_FORBIDDEN, ApiErrorCode.CHANNEL_FORBIDDEN.messageKey());
            }
            // v1 只实现 TOTP，OTP 仅留 SPI
            throw new ApiException(ApiErrorCode.NOT_IMPLEMENTED, "admin-auth.error.otp-not-implemented");
        }
        boolean verified;
        try {
            verified = operations.verifyTotp(ticket.userId(), body.code());
        } catch (MfaVerificationException e) {
            boolean usable = tickets.registerFailure(session, ticket);
            if (e.locked() || !usable) {
                throw new ApiException(ApiErrorCode.MFA_LOCKED, ApiErrorCode.MFA_LOCKED.messageKey());
            }
            throw new ApiException(ApiErrorCode.AUTH_FAILED, e.messageKey(), e.args());
        }
        if (!verified) {
            // verifyTotp 返回 false（码不匹配且未达到锁定阈值）时绝不能建会话
            boolean usable = tickets.registerFailure(session, ticket);
            ApiErrorCode code = usable ? ApiErrorCode.AUTH_FAILED : ApiErrorCode.MFA_LOCKED;
            throw new ApiException(code, "admin-auth.mfa.code-invalid");
        }
        tickets.consume(session, ticket.value());
        // 2FA 通过：清掉该账号的风险计数（ON_RISK 依赖它判断下一次登录）
        lockout.clearAllForUser(ticket.userId());
        AdminUser user = requireUser(ticket.userId());
        sessions.establish(request, user, true);
        return new ApiModels.LoginResponse("OK", null, List.of(), ApiModels.UserView.of(user));
    }

    @PostMapping("/mfa/recovery")
    public ApiModels.LoginResponse recovery(@Valid @RequestBody ApiModels.MfaRecoveryRequest body,
                                            HttpServletRequest request) {
        HttpSession session = request.getSession(true);
        PreAuthTicket ticket = tickets.require(session, body.ticket(), LoginStep.SELECT_FACTOR);
        boolean ok = operations.verifyRecoveryCode(ticket.userId(), body.code());
        if (!ok) {
            boolean usable = tickets.registerFailure(session, ticket);
            ApiErrorCode code = usable ? ApiErrorCode.AUTH_FAILED : ApiErrorCode.MFA_LOCKED;
            throw new ApiException(code, "admin-auth.error.recovery-code-invalid");
        }
        tickets.consume(session, ticket.value());
        lockout.clearAllForUser(ticket.userId());
        AdminUser user = requireUser(ticket.userId());
        sessions.establish(request, user, true);
        return new ApiModels.LoginResponse("OK", null, List.of(), ApiModels.UserView.of(user));
    }

    @PostMapping("/mfa/totp/setup/init")
    public ApiModels.TotpSetupResponse initTotp(@RequestBody(required = false) ApiModels.TotpSetupInitRequest body,
                                                HttpServletRequest request) {
        long userId = resolveBindingUser(request, body == null ? null : body.ticket());
        AdminUser user = requireUser(userId);
        TotpSetupResult setup = mfaService.beginTotpSetup(userId, user.displayName());
        return new ApiModels.TotpSetupResponse(setup.otpauthUri(), qrCodeService.toSvg(setup.otpauthUri()),
                setup.manualSecret());
    }

    @PostMapping("/mfa/totp/setup/confirm")
    public ApiModels.TotpConfirmResponse confirmTotp(
            @Valid @RequestBody ApiModels.TotpSetupConfirmRequest body,
            HttpServletRequest request) {
        HttpSession session = request.getSession(true);
        PreAuthTicket ticket = null;
        long userId;
        if (body.ticket() != null && !body.ticket().isBlank()) {
            ticket = tickets.require(session, body.ticket(), LoginStep.BIND_TOTP);
            userId = ticket.userId();
        } else {
            AdminSessionPrincipal principal = CurrentUser.require(request, sessions);
            userId = principal.userId();
        }
        List<String> recoveryCodes = operations.confirmTotpSetup(userId, body.code());

        if (ticket != null) {
            // 绑定完成即视为本次登录通过第二因素，直接建会话（第 7 段 curl 验收依赖此行为）
            tickets.consume(session, ticket.value());
            lockout.clearAllForUser(userId);
            AdminUser user = requireUser(userId);
            sessions.establish(request, user, true);
            return new ApiModels.TotpConfirmResponse(recoveryCodes, "OK", ApiModels.UserView.of(user));
        }
        return new ApiModels.TotpConfirmResponse(recoveryCodes, "OK", null);
    }

    /** v1 不发送 OTP：没有 MfaChannelSender Bean 时返回 501。 */
    @PostMapping("/mfa/otp/send")
    public ApiModels.TotpConfirmResponse sendOtp(@RequestBody(required = false) ApiModels.OtpSendRequest body) {
        throw new ApiException(ApiErrorCode.NOT_IMPLEMENTED, "admin-auth.error.otp-not-implemented");
    }

    private long resolveBindingUser(HttpServletRequest request, String ticketValue) {
        HttpSession session = request.getSession(true);
        if (ticketValue != null && !ticketValue.isBlank()) {
            return tickets.require(session, ticketValue, LoginStep.BIND_TOTP).userId();
        }
        return CurrentUser.require(request, sessions).userId();
    }

    private AdminUser requireUser(long userId) {
        return userProvider.findById(userId)
                .orElseThrow(() -> new ApiException(ApiErrorCode.TICKET_EXPIRED, "admin-auth.error.account-not-found"));
    }
}
