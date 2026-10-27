package com.aseantec.adminauth.starter.config;

import com.aseantec.adminauth.core.port.AdminIdentityRepository;
import com.aseantec.adminauth.core.port.AdminUserRepository;
import com.aseantec.adminauth.core.port.AuditRepository;
import com.aseantec.adminauth.core.port.AuditSink;
import com.aseantec.adminauth.core.port.BlindIndexer;
import com.aseantec.adminauth.core.port.ClockProvider;
import com.aseantec.adminauth.core.port.IdentityNormalizer;
import com.aseantec.adminauth.core.port.LoginAttemptRepository;
import com.aseantec.adminauth.core.port.MfaFactorRepository;
import com.aseantec.adminauth.core.port.MfaPolicy;
import com.aseantec.adminauth.core.port.PasswordVerifier;
import com.aseantec.adminauth.core.port.RecoveryCodeRepository;
import com.aseantec.adminauth.core.port.SecretCipher;
import com.aseantec.adminauth.core.crypto.RecoveryCodeHasher;
import com.aseantec.adminauth.core.service.LockoutService;
import com.aseantec.adminauth.core.service.LoginService;
import com.aseantec.adminauth.core.service.MfaService;
import com.aseantec.adminauth.core.service.PasswordService;
import com.aseantec.adminauth.core.service.TotpService;
import com.aseantec.adminauth.starter.AdminAuthProperties;
import com.aseantec.adminauth.starter.admin.AdminAuthTransactionalOperations;
import com.aseantec.adminauth.starter.admin.AdminAuthUserAdminService;
import com.aseantec.adminauth.starter.bootstrap.AdminAuthBootstrapRunner;
import com.aseantec.adminauth.starter.jdbc.JdbcAdminIdentityRepository;
import com.aseantec.adminauth.starter.jdbc.JdbcAdminUserRepository;
import com.aseantec.adminauth.starter.jdbc.JdbcAuditRepository;
import com.aseantec.adminauth.starter.jdbc.JdbcAuditSink;
import com.aseantec.adminauth.starter.jdbc.JdbcLoginAttemptRepository;
import com.aseantec.adminauth.starter.jdbc.JdbcMfaFactorRepository;
import com.aseantec.adminauth.starter.jdbc.JdbcRecoveryCodeRepository;
import com.aseantec.adminauth.starter.schema.AdminAuthSchemaInitializer;
import com.aseantec.adminauth.starter.security.AdminSessionService;
import com.aseantec.adminauth.starter.spi.AdminUserProvider;
import com.aseantec.adminauth.starter.spi.RepositoryAdminUserProvider;
import com.aseantec.adminauth.starter.startup.AdminAuthStartupCoordinator;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.session.jdbc.JdbcIndexedSessionRepository;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import javax.sql.DataSource;

/**
 * 数据访问与服务装配（依赖 DataSource）。
 * <p>仓储全部为 JdbcTemplate 实现；服务 Bean 也在此声明，且均可被宿主覆盖。</p>
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(JdbcTemplate.class)
@ConditionalOnBean(DataSource.class)
public class AdminAuthJdbcConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public JdbcTemplate adminAuthJdbcTemplate(DataSource dataSource) {
        return new JdbcTemplate(dataSource);
    }

    @Bean
    @ConditionalOnMissingBean
    public AdminUserRepository adminUserRepository(JdbcTemplate jdbc) {
        return new JdbcAdminUserRepository(jdbc);
    }

    @Bean
    @ConditionalOnMissingBean
    public AdminIdentityRepository adminIdentityRepository(JdbcTemplate jdbc) {
        return new JdbcAdminIdentityRepository(jdbc);
    }

    @Bean
    @ConditionalOnMissingBean
    public MfaFactorRepository mfaFactorRepository(JdbcTemplate jdbc) {
        return new JdbcMfaFactorRepository(jdbc);
    }

    @Bean
    @ConditionalOnMissingBean
    public RecoveryCodeRepository recoveryCodeRepository(JdbcTemplate jdbc) {
        return new JdbcRecoveryCodeRepository(jdbc);
    }

    @Bean
    @ConditionalOnMissingBean
    public LoginAttemptRepository loginAttemptRepository(JdbcTemplate jdbc) {
        return new JdbcLoginAttemptRepository(jdbc);
    }

    @Bean
    @ConditionalOnMissingBean
    public AuditRepository auditRepository(JdbcTemplate jdbc) {
        return new JdbcAuditRepository(jdbc);
    }

    @Bean
    @ConditionalOnMissingBean
    public AuditSink auditSink(AuditRepository auditRepository) {
        return new JdbcAuditSink(auditRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public AdminUserProvider adminUserProvider(AdminUserRepository users,
                                               AdminIdentityRepository identities,
                                               MfaFactorRepository factors,
                                               IdentityNormalizer normalizer,
                                               BlindIndexer blindIndexer) {
        return new RepositoryAdminUserProvider(users, identities, factors, normalizer, blindIndexer);
    }

    @Bean
    @ConditionalOnMissingBean
    public LockoutService lockoutService(LoginAttemptRepository repository,
                                         ClockProvider clock,
                                         AuditSink auditSink,
                                         AdminAuthProperties properties) {
        return new LockoutService(repository, clock, auditSink,
                properties.getLockout().getMaxAttempts(), properties.getLockout().getLockDuration());
    }

    @Bean
    @ConditionalOnMissingBean
    public LoginService loginService(AdminUserRepository users,
                                     AdminIdentityRepository identities,
                                     MfaFactorRepository factors,
                                     IdentityNormalizer normalizer,
                                     BlindIndexer blindIndexer,
                                     PasswordVerifier passwordVerifier,
                                     LockoutService lockoutService,
                                     MfaPolicy mfaPolicy,
                                     AuditSink auditSink,
                                     ClockProvider clock) {
        return new LoginService(users, identities, factors, normalizer, blindIndexer, passwordVerifier,
                lockoutService, mfaPolicy, auditSink, clock);
    }

    @Bean
    @ConditionalOnMissingBean
    public MfaService mfaService(AdminUserRepository users,
                                 MfaFactorRepository factors,
                                 RecoveryCodeRepository recoveryCodes,
                                 SecretCipher secretCipher,
                                 TotpService totpService,
                                 RecoveryCodeHasher recoveryCodeHasher,
                                 ClockProvider clock,
                                 AuditSink auditSink,
                                 AdminAuthProperties properties) {
        var mfa = properties.getMfa();
        MfaService.Settings settings = new MfaService.Settings(mfa.getTotp().getIssuer(),
                mfa.getTotp().getDigits(), mfa.getTotp().getPeriod(), mfa.getTotp().getWindow());
        return new MfaService(users, factors, recoveryCodes, secretCipher, totpService, recoveryCodeHasher,
                clock, auditSink, settings, properties.getLockout().getMaxAttempts(),
                properties.getLockout().getLockDuration());
    }

    @Bean
    @ConditionalOnMissingBean
    public PasswordService passwordService(AdminUserRepository users,
                                           PasswordVerifier passwordVerifier,
                                           ClockProvider clock,
                                           AdminAuthProperties properties) {
        return new PasswordService(users, passwordVerifier, clock, properties.getPassword().getMinLength());
    }

    @Bean
    @ConditionalOnMissingBean
    public AdminSessionService adminSessionService(ClockProvider clock,
                                                   AdminAuthProperties properties,
                                                   JdbcTemplate jdbc,
                                                   ObjectProvider<JdbcIndexedSessionRepository> sessionRepository) {
        return new AdminSessionService(clock, properties, jdbc, sessionRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public TransactionTemplate adminAuthTransactionTemplate(PlatformTransactionManager transactionManager) {
        return new TransactionTemplate(transactionManager);
    }

    @Bean
    @ConditionalOnMissingBean
    public AdminAuthUserAdminService adminAuthUserAdminService(TransactionTemplate transactionTemplate,
                                                               AdminAuthProperties properties,
                                                               AdminUserRepository users,
                                                               AdminIdentityRepository identities,
                                                               LoginAttemptRepository attempts,
                                                               IdentityNormalizer normalizer,
                                                               BlindIndexer blindIndexer,
                                                               SecretCipher secretCipher,
                                                               PasswordVerifier passwordVerifier,
                                                               com.aseantec.adminauth.core.service.StaffCodeGenerator staffCodeGenerator,
                                                               AuditSink auditSink,
                                                               ClockProvider clock) {
        return new AdminAuthUserAdminService(transactionTemplate, properties, users, identities, attempts,
                normalizer, blindIndexer, secretCipher, passwordVerifier, staffCodeGenerator, auditSink, clock);
    }

    @Bean
    @ConditionalOnMissingBean
    public AdminAuthTransactionalOperations adminAuthTransactionalOperations(TransactionTemplate transactionTemplate,
                                                                             MfaService mfaService,
                                                                             PasswordService passwordService) {
        return new AdminAuthTransactionalOperations(transactionTemplate, mfaService, passwordService);
    }

    @Bean
    @ConditionalOnMissingBean
    public AdminAuthBootstrapRunner adminAuthBootstrapRunner(AdminAuthUserAdminService userAdminService) {
        return new AdminAuthBootstrapRunner(userAdminService);
    }

    /** 在 Web 端口监听前完成迁移与引导（见 {@link AdminAuthStartupCoordinator}）。 */
    @Bean
    @ConditionalOnMissingBean
    public AdminAuthStartupCoordinator adminAuthStartupCoordinator(AdminAuthSchemaInitializer schemaInitializer,
                                                                   AdminAuthBootstrapRunner bootstrapRunner) {
        return new AdminAuthStartupCoordinator(schemaInitializer, bootstrapRunner);
    }
}
