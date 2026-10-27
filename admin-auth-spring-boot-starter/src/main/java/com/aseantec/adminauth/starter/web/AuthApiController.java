package com.aseantec.adminauth.starter.web;

import com.aseantec.adminauth.core.domain.AdminUser;
import com.aseantec.adminauth.core.domain.IdentityType;
import com.aseantec.adminauth.core.domain.LoginResult;
import com.aseantec.adminauth.core.domain.LoginStep;
import com.aseantec.adminauth.core.service.LoginService;
import com.aseantec.adminauth.starter.admin.AdminAuthTransactionalOperations;
import com.aseantec.adminauth.starter.security.AdminSessionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * 未登录接口：登录 / 初始改密 / CSRF。
 *
 * <p>登录结果按 {@link LoginStep} 分流：COMPLETE 直接建会话；其余签发 pre-auth ticket。</p>
 */
@RestController
@RequestMapping("${admin-auth.endpoint-prefix:/admin-auth}/api")
public class AuthApiController {

    private final LoginService loginService;
    private final AdminAuthTransactionalOperations operations;
    private final PreAuthTicketService tickets;
    private final AdminSessionService sessions;

    public AuthApiController(LoginService loginService,
                             AdminAuthTransactionalOperations operations,
                             PreAuthTicketService tickets,
                             AdminSessionService sessions) {
        this.loginService = loginService;
        this.operations = operations;
        this.tickets = tickets;
        this.sessions = sessions;
    }

    @PostMapping("/login")
    public ApiModels.LoginResponse login(@Valid @RequestBody ApiModels.LoginRequest body,
                                         HttpServletRequest request) {
        LoginResult result = loginService.login(body.identityType(), body.identifier(), body.password(),
                CurrentUser.ip(request), CurrentUser.userAgent(request));
        return advance(request, result, body.identityType());
    }

    @PostMapping("/password/change-initial")
    public ApiModels.LoginResponse changeInitialPassword(
            @Valid @RequestBody ApiModels.PasswordChangeInitialRequest body,
            HttpServletRequest request) {
        HttpSession session = request.getSession(true);
        PreAuthTicket ticket = tickets.require(session, body.ticket(), LoginStep.CHANGE_PASSWORD);
        operations.changePassword(ticket.userId(), body.oldPassword(), body.newPassword(), true);
        tickets.consume(session, ticket.value());
        LoginResult next = loginService.continueAfterPasswordChange(ticket.userId(), ticket.identityType());
        return advance(request, next, ticket.identityType());
    }

    /** 返回 CSRF token（同时由 CsrfFilter 写入 XSRF-TOKEN Cookie）。 */
    @GetMapping("/csrf")
    public Map<String, String> csrf(HttpServletRequest request) {
        Object attribute = request.getAttribute(CsrfToken.class.getName());
        String token = attribute instanceof CsrfToken csrfToken ? csrfToken.getToken() : "";
        return Map.of("token", token);
    }

    /** 把登录结果转成响应：完成则建会话，否则签发 ticket。 */
    private ApiModels.LoginResponse advance(HttpServletRequest request, LoginResult result, IdentityType identityType) {
        AdminUser user = result.user();
        ApiModels.UserView view = ApiModels.UserView.of(user);
        HttpSession session = request.getSession(true);
        return switch (result.step()) {
            case COMPLETE -> {
                sessions.establish(request, user, false);
                yield new ApiModels.LoginResponse("OK", null, List.of(), view);
            }
            case CHANGE_PASSWORD -> new ApiModels.LoginResponse("CHANGE_PASSWORD",
                    tickets.issue(session, user.id(), LoginStep.CHANGE_PASSWORD, identityType), List.of(), view);
            case BIND_TOTP -> new ApiModels.LoginResponse("BIND_TOTP",
                    tickets.issue(session, user.id(), LoginStep.BIND_TOTP, identityType), List.of(), view);
            case SELECT_FACTOR -> new ApiModels.LoginResponse("SELECT_FACTOR",
                    tickets.issue(session, user.id(), LoginStep.SELECT_FACTOR, identityType),
                    result.factorTypes().stream().map(Enum::name).toList(), view);
        };
    }
}
