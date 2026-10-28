package com.aseantec.adminauth.starter.config;

import com.aseantec.adminauth.core.port.ClockProvider;
import com.aseantec.adminauth.core.service.LoginService;
import com.aseantec.adminauth.core.service.LockoutService;
import com.aseantec.adminauth.core.service.MfaService;
import com.aseantec.adminauth.core.service.PasswordService;
import com.aseantec.adminauth.starter.admin.AdminAuthTransactionalOperations;
import com.aseantec.adminauth.starter.admin.AdminAuthUserAdminService;
import com.aseantec.adminauth.starter.i18n.AdminAuthMessages;
import com.aseantec.adminauth.starter.security.AdminSessionService;
import com.aseantec.adminauth.starter.web.AccountApiController;
import com.aseantec.adminauth.starter.web.AdminApiController;
import com.aseantec.adminauth.starter.web.AdminAuthPageController;
import com.aseantec.adminauth.starter.web.ApiErrorHandler;
import com.aseantec.adminauth.starter.web.AuthApiController;
import com.aseantec.adminauth.starter.web.MfaApiController;
import com.aseantec.adminauth.starter.web.PreAuthTicketService;
import com.aseantec.adminauth.starter.web.QrCodeService;
import com.aseantec.adminauth.starter.AdminAuthProperties;
import com.aseantec.adminauth.core.port.AdminUserRepository;
import com.aseantec.adminauth.core.port.AuditRepository;
import com.aseantec.adminauth.core.port.AuditSink;
import com.aseantec.adminauth.core.port.PasswordVerifier;
import com.aseantec.adminauth.starter.spi.AdminUserProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.thymeleaf.spring6.SpringTemplateEngine;

/** Web 层装配：REST 控制器、统一错误处理、内置页面控制器。 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnBean({LoginService.class, MfaService.class, PasswordService.class,
        AdminSessionService.class, AdminAuthUserAdminService.class})
public class AdminAuthWebConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public ApiErrorHandler adminAuthApiErrorHandler(AdminAuthMessages messages) {
        return new ApiErrorHandler(messages);
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthApiController adminAuthAuthApiController(LoginService loginService,
                                                        AdminAuthTransactionalOperations operations,
                                                        PreAuthTicketService tickets,
                                                        AdminSessionService sessions) {
        return new AuthApiController(loginService, operations, tickets, sessions);
    }

    @Bean
    @ConditionalOnMissingBean
    public MfaApiController adminAuthMfaApiController(MfaService mfaService,
                                                      AdminAuthTransactionalOperations operations,
                                                      PreAuthTicketService tickets,
                                                      AdminSessionService sessions,
                                                      AdminUserProvider userProvider,
                                                      QrCodeService qrCodeService,
                                                      AdminAuthProperties properties,
                                                      LockoutService lockoutService) {
        return new MfaApiController(mfaService, operations, tickets, sessions, userProvider, qrCodeService,
                properties, lockoutService);
    }

    @Bean
    @ConditionalOnMissingBean
    public AccountApiController adminAuthAccountApiController(AdminSessionService sessions,
                                                              AdminUserProvider userProvider,
                                                              AdminUserRepository users,
                                                              MfaService mfaService,
                                                              AdminAuthTransactionalOperations operations,
                                                              PasswordVerifier passwordVerifier,
                                                              com.aseantec.adminauth.core.port.MfaPolicy mfaPolicy,
                                                              AuditSink auditSink,
                                                              ClockProvider clock) {
        return new AccountApiController(sessions, userProvider, users, mfaService, operations,
                passwordVerifier, mfaPolicy, auditSink, clock);
    }

    @Bean
    @ConditionalOnMissingBean
    public AdminApiController adminAuthAdminApiController(AdminSessionService sessions,
                                                          AdminUserRepository users,
                                                          AdminAuthUserAdminService userAdminService,
                                                          AdminAuthTransactionalOperations operations,
                                                          AuditRepository auditRepository,
                                                          AuditSink auditSink,
                                                          AdminAuthProperties properties,
                                                          ClockProvider clock) {
        return new AdminApiController(sessions, users, userAdminService, operations,
                auditRepository, auditSink, properties, clock);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnClass(SpringTemplateEngine.class)
    @ConditionalOnProperty(prefix = "admin-auth.ui", name = "enabled", havingValue = "true", matchIfMissing = true)
    public AdminAuthPageController adminAuthPageController(AdminAuthMessages messages) {
        return new AdminAuthPageController(messages);
    }
}
