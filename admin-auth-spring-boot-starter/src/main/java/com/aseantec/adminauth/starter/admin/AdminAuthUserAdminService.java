package com.aseantec.adminauth.starter.admin;

import com.aseantec.adminauth.core.domain.AdminIdentity;
import com.aseantec.adminauth.core.domain.AdminUser;
import com.aseantec.adminauth.core.domain.AuditEntry;
import com.aseantec.adminauth.core.domain.AuditEvent;
import com.aseantec.adminauth.core.domain.AuditResult;
import com.aseantec.adminauth.core.domain.IdentityStatus;
import com.aseantec.adminauth.core.domain.IdentityType;
import com.aseantec.adminauth.core.domain.UserStatus;
import com.aseantec.adminauth.core.port.AdminIdentityRepository;
import com.aseantec.adminauth.core.port.AdminUserRepository;
import com.aseantec.adminauth.core.port.AuditSink;
import com.aseantec.adminauth.core.port.BlindIndexer;
import com.aseantec.adminauth.core.port.ClockProvider;
import com.aseantec.adminauth.core.port.IdentityNormalizer;
import com.aseantec.adminauth.core.port.LoginAttemptRepository;
import com.aseantec.adminauth.core.port.PasswordVerifier;
import com.aseantec.adminauth.core.port.SecretCipher;
import com.aseantec.adminauth.core.service.StaffCodeGenerator;
import com.aseantec.adminauth.core.util.Masking;
import com.aseantec.adminauth.starter.AdminAuthProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;

/**
 * 管理员账号生命周期：bootstrap、创建、停用/启用、解锁、重置密码、分页查询。
 *
 * <p>所有多写操作在 {@link TransactionTemplate} 中执行（账号 + 标识 + 审计要么全成功要么全回滚）。
 * 会话失效由调用方在事务提交后执行，避免把 Spring Session 写入包进业务事务。</p>
 */
public class AdminAuthUserAdminService {

    private static final Logger log = LoggerFactory.getLogger(AdminAuthUserAdminService.class);
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    private static final String LOWER = "abcdefghijkmnopqrstuvwxyz";
    private static final String DIGITS = "23456789";
    private static final String SYMBOLS = "!@#$%^&*";

    private final TransactionTemplate transactionTemplate;
    private final AdminAuthProperties properties;
    private final AdminUserRepository users;
    private final AdminIdentityRepository identities;
    private final LoginAttemptRepository attempts;
    private final IdentityNormalizer normalizer;
    private final BlindIndexer blindIndexer;
    private final SecretCipher secretCipher;
    private final PasswordVerifier passwordVerifier;
    private final StaffCodeGenerator staffCodeGenerator;
    private final AuditSink auditSink;
    private final ClockProvider clock;

    public AdminAuthUserAdminService(TransactionTemplate transactionTemplate,
                                     AdminAuthProperties properties,
                                     AdminUserRepository users,
                                     AdminIdentityRepository identities,
                                     LoginAttemptRepository attempts,
                                     IdentityNormalizer normalizer,
                                     BlindIndexer blindIndexer,
                                     SecretCipher secretCipher,
                                     PasswordVerifier passwordVerifier,
                                     StaffCodeGenerator staffCodeGenerator,
                                     AuditSink auditSink,
                                     ClockProvider clock) {
        this.transactionTemplate = transactionTemplate;
        this.properties = properties;
        this.users = users;
        this.identities = identities;
        this.attempts = attempts;
        this.normalizer = normalizer;
        this.blindIndexer = blindIndexer;
        this.secretCipher = secretCipher;
        this.passwordVerifier = passwordVerifier;
        this.staffCodeGenerator = staffCodeGenerator;
        this.auditSink = auditSink;
        this.clock = clock;
    }

    /** 创建结果：临时密码只在这一次返回，落库只有 BCrypt。 */
    public record CreatedUser(long userId, String emailMask, String staffCode, String temporaryPassword) {
    }

    /**
     * 启动引导：无指定角色账号时创建初始管理员（幂等；多实例并发由唯一键兜底）。
     */
    public void bootstrapAdminIfMissing() {
        var bootstrap = properties.getBootstrap();
        if (!bootstrap.isEnabled()) {
            log.debug("admin-auth.bootstrap.enabled=false，跳过初始账号创建");
            return;
        }
        if (isBlank(bootstrap.getEmail()) || isBlank(bootstrap.getPassword())) {
            log.warn("admin-auth.bootstrap 已启用但未配置 email/password，跳过初始账号创建");
            return;
        }
        if (users.countByRole(bootstrap.getRole()) > 0) {
            log.debug("已存在 {} 账号，跳过 bootstrap", bootstrap.getRole());
            return;
        }
        try {
            CreatedUser created = transactionTemplate.execute(status -> createInternal(
                    bootstrap.getDisplayName(), bootstrap.getRole(), bootstrap.getEmail(),
                    bootstrap.getStaffCode(), bootstrap.getPassword(), null, AuditEvent.BOOTSTRAP));
            if (created != null) {
                log.info("admin-auth 初始账号已创建: {}（{}），首次登录须改密并绑定 TOTP",
                        created.emailMask(), bootstrap.getRole());
            }
        } catch (DuplicateKeyException race) {
            // 多实例同时启动：另一个实例已完成，唯一键（激活标识）会拦住重复插入
            log.info("admin-auth bootstrap 已由其它实例完成，跳过");
        }
    }

    /** 管理台创建管理员：默认强制首次改密。 */
    public CreatedUser createUser(String displayName, String role, String email, String staffCode,
                                  String password, Long actorUserId) {
        try {
            CreatedUser created = transactionTemplate.execute(status -> createInternal(
                    displayName, role, email, staffCode, password, actorUserId, AuditEvent.USER_CREATE));
            if (created == null) {
                throw new IllegalStateException("创建账号失败");
            }
            return created;
        } catch (DuplicateKeyException race) {
            // 并发下预检查可能失效：唯一键兜底，转为可读的 400 而不是 500
            throw new IllegalStateException("邮箱或 STAFF_CODE 已被使用，请更换后重试");
        }
    }

    /** 管理员重置密码：生成一次性临时密码、token_version+1、强制下次改密。 */
    public String resetPassword(long userId, Long actorUserId) {
        String temporaryPassword = transactionTemplate.execute(status -> {
            AdminUser user = requireUser(userId);
            String temp = generateTemporaryPassword();
            users.updatePassword(user.id(), passwordVerifier.hash(temp), passwordVerifier.algorithm(),
                    clock.now(), true);
            recordAudit(actorUserId, user.id(), AuditEvent.PASSWORD_RESET, "{\"reason\":\"ADMIN_RESET\"}");
            return temp;
        });
        if (temporaryPassword == null) {
            throw new IllegalStateException("重置密码失败");
        }
        return temporaryPassword;
    }

    public void updateStatus(long userId, boolean enabled, Long actorUserId) {
        transactionTemplate.executeWithoutResult(status -> {
            AdminUser user = requireUser(userId);
            users.updateStatus(user.id(), enabled ? UserStatus.ACTIVE : UserStatus.DISABLED);
            recordAudit(actorUserId, user.id(),
                    enabled ? AuditEvent.USER_ENABLE : AuditEvent.USER_DISABLE, null);
        });
    }

    /** 管理员解锁：清空该账号在所有 IP 上的失败计数。 */
    public void unlock(long userId, Long actorUserId) {
        transactionTemplate.executeWithoutResult(status -> {
            requireUser(userId);
            attempts.clearAllForUser(userId);
            recordAudit(actorUserId, userId, AuditEvent.USER_UNLOCK, "{\"reason\":\"ADMIN_UNLOCK\"}");
        });
    }

    public List<AdminUser> findPage(int page, int size) {
        int safePage = Math.max(0, page);
        int safeSize = Math.max(1, Math.min(size, 100));
        return users.findPage(safePage * safeSize, safeSize);
    }

    public long countAll() {
        return users.countAll();
    }

    public AdminUser requireUser(long userId) {
        return users.findById(userId)
                .orElseThrow(() -> new IllegalStateException("账号不存在: " + userId));
    }

    public List<AdminIdentity> identitiesOf(long userId) {
        return identities.findByUserId(userId);
    }

    // ---------- internals ----------

    private CreatedUser createInternal(String displayName, String role, String email, String staffCode,
                                       String password, Long actorUserId, AuditEvent event) {
        Instant now = clock.now();
        String normalizedEmail = normalizer.normalize(IdentityType.EMAIL, email);
        byte[] emailHash = blindIndexer.index(IdentityType.EMAIL, normalizedEmail);
        if (identities.findActiveByTypeAndHash(IdentityType.EMAIL, emailHash).isPresent()) {
            throw new IllegalStateException("邮箱已被使用: " + Masking.email(normalizedEmail));
        }

        String effectivePassword = isBlank(password) ? generateTemporaryPassword() : password;
        AdminUser draft = new AdminUser(0L, displayName, role, UserStatus.ACTIVE,
                passwordVerifier.hash(effectivePassword), passwordVerifier.algorithm(),
                true, 0, -1, 0, null, null, now, now);
        long userId = users.insert(draft);
        if (userId <= 0) {
            throw new IllegalStateException("创建账号失败：未取得主键");
        }

        insertIdentity(userId, IdentityType.EMAIL, normalizedEmail, Masking.email(normalizedEmail), true, now);
        String resolvedStaffCode = resolveStaffCode(userId, staffCode);
        insertIdentity(userId, IdentityType.STAFF_CODE, resolvedStaffCode,
                Masking.staffCode(resolvedStaffCode), false, now);

        recordAudit(actorUserId, userId, event, "{\"role\":\"" + role + "\"}");
        return new CreatedUser(userId, Masking.email(normalizedEmail), resolvedStaffCode, effectivePassword);
    }

    private void insertIdentity(long userId, IdentityType type, String normalizedValue,
                                String mask, boolean primary, Instant now) {
        byte[] encrypted = secretCipher.encrypt(normalizedValue.getBytes(StandardCharsets.UTF_8));
        byte[] hash = blindIndexer.index(type, normalizedValue);
        identities.insert(new AdminIdentity(0L, userId, type, encrypted, secretCipher.keyVersion(), hash,
                mask, now, null, "", primary, IdentityStatus.ACTIVE));
    }

    private String resolveStaffCode(long userId, String explicit) {
        if (!isBlank(explicit)) {
            String normalized = normalizer.normalize(IdentityType.STAFF_CODE, explicit);
            byte[] hash = blindIndexer.index(IdentityType.STAFF_CODE, normalized);
            if (identities.findActiveByTypeAndHash(IdentityType.STAFF_CODE, hash).isPresent()) {
                throw new IllegalStateException("STAFF_CODE 已被使用: " + Masking.staffCode(normalized));
            }
            return normalized;
        }
        for (int attempt = 0; attempt < 5; attempt++) {
            String candidate = staffCodeGenerator.generate(userId + attempt * 1000L);
            byte[] hash = blindIndexer.index(IdentityType.STAFF_CODE,
                    normalizer.normalize(IdentityType.STAFF_CODE, candidate));
            if (identities.findActiveByTypeAndHash(IdentityType.STAFF_CODE, hash).isEmpty()) {
                return candidate;
            }
        }
        throw new IllegalStateException("STAFF_CODE 生成冲突，请在请求中显式指定");
    }

    /** 生成满足长度要求的一次性密码：大小写、数字、符号各至少一个。 */
    public String generateTemporaryPassword() {
        int length = Math.max(16, properties.getPassword().getMinLength());
        char[] chars = new char[length];
        String all = UPPER + LOWER + DIGITS + SYMBOLS;
        chars[0] = UPPER.charAt(RANDOM.nextInt(UPPER.length()));
        chars[1] = LOWER.charAt(RANDOM.nextInt(LOWER.length()));
        chars[2] = DIGITS.charAt(RANDOM.nextInt(DIGITS.length()));
        chars[3] = SYMBOLS.charAt(RANDOM.nextInt(SYMBOLS.length()));
        for (int i = 4; i < length; i++) {
            chars[i] = all.charAt(RANDOM.nextInt(all.length()));
        }
        for (int i = length - 1; i > 0; i--) {
            int j = RANDOM.nextInt(i + 1);
            char tmp = chars[i];
            chars[i] = chars[j];
            chars[j] = tmp;
        }
        return new String(chars);
    }

    private void recordAudit(Long actorUserId, long userId, AuditEvent event, String detail) {
        auditSink.record(new AuditEntry(userId, actorUserId, "", "", "", event, AuditResult.SUCCESS,
                "", "", detail, clock.now()));
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
