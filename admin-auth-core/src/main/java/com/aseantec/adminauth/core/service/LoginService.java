package com.aseantec.adminauth.core.service;

import com.aseantec.adminauth.core.domain.AdminIdentity;
import com.aseantec.adminauth.core.domain.AdminUser;
import com.aseantec.adminauth.core.domain.AuditEntry;
import com.aseantec.adminauth.core.domain.AuditEvent;
import com.aseantec.adminauth.core.domain.AuditResult;
import com.aseantec.adminauth.core.domain.IdentityType;
import com.aseantec.adminauth.core.domain.LoginFailedException;
import com.aseantec.adminauth.core.domain.LoginFailure;
import com.aseantec.adminauth.core.domain.LoginResult;
import com.aseantec.adminauth.core.domain.LoginStep;
import com.aseantec.adminauth.core.domain.MfaDecision;
import com.aseantec.adminauth.core.domain.MfaFactor;
import com.aseantec.adminauth.core.port.AdminIdentityRepository;
import com.aseantec.adminauth.core.port.AdminUserRepository;
import com.aseantec.adminauth.core.port.AuditSink;
import com.aseantec.adminauth.core.port.BlindIndexer;
import com.aseantec.adminauth.core.port.ClockProvider;
import com.aseantec.adminauth.core.port.IdentityNormalizer;
import com.aseantec.adminauth.core.port.MfaFactorRepository;
import com.aseantec.adminauth.core.port.MfaPolicy;
import com.aseantec.adminauth.core.port.PasswordVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * 登录编排（第一因素）。
 *
 * <p><b>链路</b></p>
 * <ol>
 *   <li>规范化标识（EMAIL 小写 / PHONE 去分隔符 / STAFF_CODE 大写）；</li>
 *   <li>计算盲索引 HMAC(indexKey, type|normalized|v1)；</li>
 *   <li>锁定检查（标识+IP）；</li>
 *   <li>按盲索引查启用标识 → 查账号；</li>
 *   <li>恒定耗时 BCrypt：账号不存在/停用时也跑一次 dummy hash；</li>
 *   <li>失败：计数（user 维度合并）并按阈值锁定；成功：清计数、更新时间；</li>
 *   <li>{@code must_change_password} 优先于 2FA；</li>
 *   <li>2FA 策略判定 → COMPLETE / SELECT_FACTOR / BIND_TOTP。</li>
 * </ol>
 */
public class LoginService {

    private static final Logger log = LoggerFactory.getLogger(LoginService.class);

    private final AdminUserRepository users;
    private final AdminIdentityRepository identities;
    private final MfaFactorRepository factors;
    private final IdentityNormalizer normalizer;
    private final BlindIndexer blindIndexer;
    private final PasswordVerifier passwordVerifier;
    private final LockoutService lockout;
    private final MfaPolicy mfaPolicy;
    private final AuditSink audit;
    private final ClockProvider clock;
    private final String dummyHash;

    public LoginService(AdminUserRepository users,
                        AdminIdentityRepository identities,
                        MfaFactorRepository factors,
                        IdentityNormalizer normalizer,
                        BlindIndexer blindIndexer,
                        PasswordVerifier passwordVerifier,
                        LockoutService lockout,
                        MfaPolicy mfaPolicy,
                        AuditSink audit,
                        ClockProvider clock) {
        this.users = users;
        this.identities = identities;
        this.factors = factors;
        this.normalizer = normalizer;
        this.blindIndexer = blindIndexer;
        this.passwordVerifier = passwordVerifier;
        this.lockout = lockout;
        this.mfaPolicy = mfaPolicy;
        this.audit = audit;
        this.clock = clock;
        // 启动时生成一次 dummy hash：账号不存在时也执行同样成本的 BCrypt，避免时间侧信道枚举账号
        this.dummyHash = passwordVerifier.hash(UUID.randomUUID().toString());
    }

    /**
     * 第一因素登录。
     *
     * @throws LoginFailedException 认证失败（AUTH_FAILED）或锁定（LOCKED）
     */
    public LoginResult login(IdentityType type, String identifier, String password, String ip, String userAgent) {
        Instant now = clock.now();
        String normalized;
        try {
            normalized = normalizer.normalize(type, identifier);
        } catch (RuntimeException e) {
            throw new LoginFailedException(LoginFailure.AUTH_FAILED);
        }
        byte[] index = blindIndexer.index(type, normalized);

        // 1) 登录前锁定检查：已锁定直接拒绝，不消耗 BCrypt
        if (lockout.isLocked(index, ip)) {
            recordAudit(null, type, null, AuditEvent.LOGIN_FAIL, AuditResult.FAIL, ip, userAgent,
                    "{\"reason\":\"LOCKED\"}", now);
            throw new LoginFailedException(LoginFailure.LOCKED);
        }

        AdminIdentity identity = identities.findActiveByTypeAndHash(type, index).orElse(null);
        AdminUser user = identity == null ? null : users.findById(identity.userId()).orElse(null);

        if (user != null && lockout.isUserLocked(user.id(), ip)) {
            recordAudit(user, type, identity, AuditEvent.LOGIN_FAIL, AuditResult.FAIL, ip, userAgent,
                    "{\"reason\":\"USER_LOCKED\"}", now);
            throw new LoginFailedException(LoginFailure.LOCKED);
        }

        // 2) 恒定耗时校验：账号不存在或停用时也走一次 BCrypt
        boolean usableUser = user != null && user.active();
        boolean passwordOk = passwordVerifier.verify(password, usableUser ? user.passwordHash() : dummyHash);

        if (!usableUser || !passwordOk) {
            var failure = lockout.registerFailure(index, ip, user == null ? null : user.id());
            recordAudit(user, type, identity, AuditEvent.LOGIN_FAIL, AuditResult.FAIL, ip, userAgent,
                    "{\"reason\":\"BAD_CREDENTIALS\"}", now);
            if (failure.locked()) {
                throw new LoginFailedException(LoginFailure.LOCKED);
            }
            throw new LoginFailedException(LoginFailure.AUTH_FAILED);
        }

        // 3) 成功：清计数、更新时间、审计
        lockout.clear(index, ip, user.id());
        users.updateLastLogin(user.id(), now);
        recordAudit(user, type, identity, AuditEvent.LOGIN_PASSWORD_OK, AuditResult.SUCCESS, ip, userAgent, null, now);

        // 4) 初始改密优先于 2FA
        if (user.mustChangePassword()) {
            return new LoginResult(LoginStep.CHANGE_PASSWORD, user, List.of());
        }
        return mfaStep(user, type);
    }

    /** 初始改密完成后继续判定 2FA 步骤。 */
    public LoginResult continueAfterPasswordChange(long userId, IdentityType identityType) {
        AdminUser user = users.findById(userId)
                .orElseThrow(() -> new LoginFailedException(LoginFailure.AUTH_FAILED));
        return mfaStep(user, identityType);
    }

    /** 2FA 策略判定：COMPLETE / SELECT_FACTOR / BIND_TOTP。 */
    private LoginResult mfaStep(AdminUser user, IdentityType identityType) {
        List<MfaFactor> active = factors.findActiveByUserId(user.id());
        MfaDecision decision = mfaPolicy.decide(user, identityType, active);
        if (!decision.required()) {
            return new LoginResult(LoginStep.COMPLETE, user, List.of());
        }
        if (decision.bindTotpRequired()) {
            return new LoginResult(LoginStep.BIND_TOTP, user, List.of());
        }
        return new LoginResult(LoginStep.SELECT_FACTOR, user, decision.factorTypes());
    }

    private void recordAudit(AdminUser user,
                             IdentityType type,
                             AdminIdentity identity,
                             AuditEvent event,
                             AuditResult result,
                             String ip,
                             String userAgent,
                             String detail,
                             Instant now) {
        try {
            audit.record(new AuditEntry(
                    user == null ? null : user.id(),
                    null,
                    type == null ? "" : type.name(),
                    "",
                    identity == null ? "" : identity.valueMask(),
                    event,
                    result,
                    ip,
                    userAgent,
                    detail,
                    now));
        } catch (RuntimeException e) {
            log.warn("审计写入失败（已忽略，不影响登录）: {}", e.getMessage());
        }
    }
}
